import { sql } from "../index";
import type { AuthContext, User, UserRole, ApiKeyScope } from "../../types";
import { validateApiKey } from "../routes/apikeys";

export type { AuthContext };

const SESSION_COOKIE = "session";

function parseCookies(cookieHeader: string | null): Record<string, string> {
	if (!cookieHeader) return {};
	return Object.fromEntries(
		cookieHeader.split(";").map((cookie) => {
			const [key, ...rest] = cookie.trim().split("=");
			return [key, rest.join("=")];
		}),
	);
}

export async function getAuthContext(req: Request): Promise<AuthContext> {
	const authHeader = req.headers.get("authorization");
	if (authHeader?.startsWith("Bearer ")) {
		const apiKey = authHeader.slice(7);
		const result = await validateApiKey(apiKey);

		if (result.valid && result.userId) {
			const rows = await sql`
				SELECT id, username, email, role, access_ids
				FROM users
				WHERE id = ${result.userId}
			`;

			if (rows.length > 0) {
				const row = rows[0];
				const user: User = {
					id: row.id as string,
					username: row.username as string,
					email: row.email as string,
					role: row.role as UserRole,
					accessIds: (row.access_ids as string[]) || [],
				};

				return {
					user,
					isAuthenticated: true,
					isAdmin: user.role === "admin",
					apiKeyScopes: result.scopes,
					apiKeyId: result.keyId,
				};
			}
		}

		return { user: null, isAuthenticated: false, isAdmin: false };
	}

	const cookies = parseCookies(req.headers.get("cookie"));
	const sessionId = cookies[SESSION_COOKIE];

	if (!sessionId) {
		return { user: null, isAuthenticated: false, isAdmin: false };
	}

	const rows = await sql`
		SELECT id, username, email, role, access_ids
		FROM users
		WHERE id = ${sessionId}
	`;

	if (rows.length === 0) {
		return { user: null, isAuthenticated: false, isAdmin: false };
	}

	const row = rows[0];
	const user: User = {
		id: row.id as string,
		username: row.username as string,
		email: row.email as string,
		role: row.role as UserRole,
		accessIds: (row.access_ids as string[]) || [],
	};

	return {
		user,
		isAuthenticated: true,
		isAdmin: user.role === "admin",
	};
}

export function requireAuth(auth: AuthContext): auth is AuthContext & { user: User } {
	return auth.isAuthenticated && auth.user !== null;
}

export function requireAdmin(auth: AuthContext): auth is AuthContext & { user: User } {
	return auth.isAuthenticated && auth.isAdmin && auth.user !== null;
}

export function requireSession(auth: AuthContext): boolean {
	return auth.isAuthenticated && !auth.apiKeyId;
}

export function requireScope(auth: AuthContext, scope: ApiKeyScope): boolean {
	if (!auth.apiKeyScopes) {
		return true;
	}
	return auth.apiKeyScopes.includes(scope);
}

export function requireAnyScope(auth: AuthContext, scopes: ApiKeyScope[]): boolean {
	if (!auth.apiKeyScopes) {
		return true;
	}
	return scopes.some((scope) => auth.apiKeyScopes!.includes(scope));
}
