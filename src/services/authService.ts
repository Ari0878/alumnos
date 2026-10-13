import jwt from "jsonwebtoken";
import type { SignOptions } from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { config } from "../config/env";
import { conflict, unauthorized } from "../errors/httpError";
import type { UserRepository } from "../repositories/userRepository";
import type { TokenRepository } from "../repositories/tokenRepository";
import type { StudentRepository } from "../repositories/studentRepository";

export interface PublicUser {
  id: number;
  email: string;
  created_at: string;
}

export interface TokenPayload {
  iss: string; // issuer
  sub: string; // subject 
  aud: string; // audience
  exp: number; // expiration time
  iat: number; // issued at
  jti: string; // JWT ID
  email: string;
  role: "user" | "student";
}

export class AuthService {
  constructor(
    private readonly users: UserRepository,
    private readonly tokens: TokenRepository,
    private readonly students: StudentRepository,
  ) {}

  async register(email: string, password: string): Promise<PublicUser> {
    if (this.users.findByEmail(email)) {
      throw conflict("Ya existe un usuario con ese correo electrónico");
    }
    const hash = await bcrypt.hash(password, config.bcryptRounds);
    const user = this.users.create(email, hash);
    return { id: user.id, email: user.email, created_at: user.created_at };
  }

  async login(
    email: string,
    password: string,
  ): Promise<{ token: string; user: PublicUser }> {
    // Se puede iniciar sesión con una cuenta de usuario (registro) o con
    // las credenciales de un estudiante (email + password).
    const user = this.users.findByEmail(email);
    const student = user ? undefined : this.students.findByEmail(email);
    const account = user
      ? { id: user.id, email: user.email, hash: user.password_hash, kind: "user" }
      : student
        ? {
            id: student.id,
            email: student.email,
            hash: student.password_hash,
            kind: "student",
          }
        : undefined;

    if (!account || account.hash === "") {
      throw unauthorized("Credenciales inválidas");
    }

    const ok = await bcrypt.compare(password, account.hash);
    if (!ok) throw unauthorized("Credenciales inválidas");

    const options: SignOptions = {
      expiresIn: config.jwtExpiresIn as SignOptions["expiresIn"],
      jwtid: randomUUID(),
      // issuer: "alumnos-api",
      // audience: "alumnos-app",
    };
    const token = jwt.sign(
      { sub: String(account.id), email: account.email, role: account.kind },
      config.jwtSecret,
      options,
    );
    return { token, user: { id: account.id, email: account.email, created_at: account.kind === "user" ? (this.users.findById(account.id)?.created_at ?? "") : "" } };
  }

  /** Revoca el token actual (logout) usando su jti y expiración. */
  logout(payload: TokenPayload): void {
    this.tokens.revoke(payload.jti, payload.exp);
  }

  verify(token: string): TokenPayload {
    try {
      const decoded = jwt.verify(token, config.jwtSecret) as TokenPayload;
      if (!decoded.jti) throw new Error("token sin jti");
      if (this.tokens.isRevoked(decoded.jti)) {
        throw unauthorized("La sesión ha sido cerrada");
      }
      return decoded;
    } catch (err) {
      if (err instanceof Error && err.name === "HttpError") throw err;
      throw unauthorized("Token inválido o expirado");
    }
  }

  /** Obtiene el usuario completo usando el ID */
  getUserFromClaim(payload: TokenPayload): (PublicUser & { iss: string; aud: string; exp: number; iat: number; jti: string }) | { id: number; email: string; nombre: string; apellido: string; matricula: string; created_at: string; updated_at: string; iss: string; aud: string; exp: number; iat: number; jti: string } | null {
    const userId = parseInt(payload.sub, 10);
    
    if (payload.role === "user") {
      const user = this.users.findById(userId);
      if (!user) return null;
      return { 
        id: user.id, 
        email: user.email, 
        created_at: user.created_at, 
        iss: payload.iss,
        aud: payload.aud,
        exp: payload.exp,
        iat: payload.iat,
        jti: payload.jti,
      };
    } else if (payload.role === "student") {
      const student = this.students.findById(userId);
      if (!student) return null;
      return {
        id: student.id,
        email: student.email,
        nombre: student.nombre,
        apellido: student.apellido,
        matricula: student.matricula,
        created_at: student.created_at,
        updated_at: student.updated_at,
        iss: payload.iss,
        aud: payload.aud,
        exp: payload.exp,
        iat: payload.iat,
        jti: payload.jti,
      };
    }
    
    return null;
  }
}
