import { CryptoHasher, randomUUIDv7 } from "bun";
import { sql } from "../index";
import { USER_ROLES, isUserRole } from "../../types";
import type { UserAccount, UserRole } from "../../types";
import { getAuthContext, requireAuth, requireAdmin, requireSession } from "../utils/auth";
import { ok, created, noContent, badRequest, unauthorized, forbidden, notFound, conflict } from "../utils/response";

function hashPassword(password: string): string {
	return new CryptoHasher("sha256").update(password).digest("hex");
}

function verifyPassword(password: string, hash: string): boolean {
	return hashPassword(password) === hash;
}

export async function login(req: Request): Promise<Response> {
	const body = await req.json();
	const { username, password } = body;

	if (!username || !password) {
		return badRequest("Username and password required");
	}

	const rows = await sql`
		SELECT id, username, email, password_hash, role, access_ids
		FROM users
		WHERE username = ${username}
	`;

	if (rows.length === 0) {
		return unauthorized("Invalid credentials");
	}

	const row = rows[0];
	const valid = verifyPassword(password, row.password_hash as string);

	if (!valid) {
		return unauthorized("Invalid credentials");
	}

	return ok({
		user: {
			id: row.id,
			username: row.username,
			email: row.email,
			role: row.role,
			accessIds: row.access_ids || [],
		},
	});
}

export async function register(req: Request): Promise<Response> {
	const body = await req.json();
	const { username, email, password, inviteCode, role = "viewer" } = body;

	if (!username || !email || !password) {
		return badRequest("Username, email, and password required");
	}

	if (password.length < 8) {
		return badRequest("Password must be at least 8 characters");
	}

	const countResult = await sql`SELECT COUNT(*) as count FROM users`;
	const count = Number(countResult[0]?.count ?? 0);
	const isFirstUser = count === 0;
	const assignedRole = isFirstUser ? "admin" : role;

	let inviteId: string | null = null;
	if (!isFirstUser) {
		if (!inviteCode) {
			return badRequest("Invite code required");
		}

		const inviteRows = await sql`
			SELECT id, used_by, expires_at
			FROM invites
			WHERE code = ${inviteCode.toUpperCase()}
		`;

		if (inviteRows.length === 0) {
			return badRequest("Invalid invite code");
		}

		const invite = inviteRows[0];

		if (invite.used_by) {
			return badRequest("Invite code already used");
		}

		if (invite.expires_at && new Date(invite.expires_at as string) < new Date()) {
			return badRequest("Invite code expired");
		}

		inviteId = invite.id as string;
	}

	const id = randomUUIDv7();
	const passwordHash = hashPassword(password);

	try {
		await sql.begin(async (tx) => {
			await tx`
				INSERT INTO users (id, username, email, password_hash, role)
				VALUES (${id}, ${username}, ${email}, ${passwordHash}, ${assignedRole})
			`;
			if (inviteId) {
				const claimed = await tx`
					UPDATE invites
					SET used_by = ${id}, used_at = NOW()
					WHERE id = ${inviteId} AND used_by IS NULL
					RETURNING id
				`;
				if (claimed.length === 0) {
					throw new Error("INVITE_USED");
				}
			}
		});
	} catch (err) {
		const message = err instanceof Error ? err.message : "";
		const code = (err as { errno?: string } | null)?.errno;
		if (message === "INVITE_USED") {
			return badRequest("Invite code already used");
		}
		if (code === "23505" || message.toLowerCase().includes("duplicate") || message.toLowerCase().includes("unique")) {
			return conflict("Username or email already exists");
		}
		throw err;
	}

	return created({
		user: {
			id,
			username,
			email,
			role: assignedRole,
			accessIds: [],
		},
	});
}

export async function isFirstUser(): Promise<Response> {
	const countResult = await sql`SELECT COUNT(*) as count FROM users`;
	const count = Number(countResult[0]?.count ?? 0);
	return ok({ isFirstUser: count === 0 });
}

export async function getUser(
	req: Request,
	_url: URL,
	params?: Record<string, string>,
): Promise<Response> {
	const auth = await getAuthContext(req);
	if (!requireAuth(auth)) {
		return unauthorized();
	}

	const id = params?.id;
	if (!id) {
		return badRequest("User ID required");
	}

	if (auth.user.id !== id && !auth.isAdmin) {
		return forbidden("Cannot access other users");
	}

	const rows = await sql`
		SELECT id, username, email, role, access_ids
		FROM users
		WHERE id = ${id}
	`;

	if (rows.length === 0) {
		return notFound("User not found");
	}

	const row = rows[0];
	return ok({
		user: {
			id: row.id,
			username: row.username,
			email: row.email,
			role: row.role,
			accessIds: row.access_ids || [],
		},
	});
}

export async function changePassword(
	req: Request,
	_url: URL,
	params?: Record<string, string>,
): Promise<Response> {
	const auth = await getAuthContext(req);
	if (!requireAuth(auth)) {
		return unauthorized();
	}

	const id = params?.id;
	if (!id) {
		return badRequest("User ID required");
	}

	if (auth.user.id !== id) {
		return forbidden("Cannot change other users' passwords");
	}

	const body = await req.json();
	const { currentPassword, newPassword } = body;

	if (!currentPassword || !newPassword) {
		return badRequest("Current and new password required");
	}

	if (newPassword.length < 8) {
		return badRequest("New password must be at least 8 characters");
	}

	const rows = await sql`
		SELECT password_hash FROM users WHERE id = ${id}
	`;

	if (rows.length === 0) {
		return notFound("User not found");
	}

	const valid = verifyPassword(currentPassword, rows[0].password_hash as string);
	if (!valid) {
		return unauthorized("Current password is incorrect");
	}

	const newHash = hashPassword(newPassword);
	await sql`
		UPDATE users SET password_hash = ${newHash} WHERE id = ${id}
	`;

	return ok({ message: "Password updated" });
}

async function requireUserAdmin(req: Request) {
	const auth = await getAuthContext(req);
	if (!requireAuth(auth)) {
		return unauthorized();
	}
	if (!requireSession(auth)) {
		return forbidden("User management requires a session, not an API key");
	}
	if (!requireAdmin(auth)) {
		return forbidden("Admin access required");
	}
	return auth;
}

function rowToUserAccount(row: Record<string, unknown>): UserAccount {
	return {
		id: row.id as string,
		username: row.username as string,
		email: row.email as string,
		role: row.role as UserRole,
		createdAt: row.created_at as string,
	};
}

export async function listUsers(req: Request): Promise<Response> {
	const auth = await requireUserAdmin(req);
	if (auth instanceof Response) return auth;

	const rows = await sql`
		SELECT id, username, email, role, created_at
		FROM users
		ORDER BY created_at ASC
	`;

	return ok({
		users: rows.map(rowToUserAccount),
	});
}

export async function updateUserRole(
	req: Request,
	_url: URL,
	params?: Record<string, string>,
): Promise<Response> {
	const auth = await requireUserAdmin(req);
	if (auth instanceof Response) return auth;

	const id = params?.id;
	if (!id) {
		return badRequest("User ID required");
	}

	if (id === auth.user.id) {
		return badRequest("Cannot change your own role");
	}

	const body = await req.json();
	const { role } = body;

	if (!isUserRole(role)) {
		return badRequest(`Role must be one of: ${USER_ROLES.join(", ")}`);
	}

	const updated = await sql`
		UPDATE users SET role = ${role}, updated_at = NOW()
		WHERE id = ${id}
		RETURNING id, username, email, role, created_at
	`;

	if (updated.length === 0) {
		return notFound("User not found");
	}

	return ok({ user: rowToUserAccount(updated[0]) });
}

export async function resetUserPassword(
	req: Request,
	_url: URL,
	params?: Record<string, string>,
): Promise<Response> {
	const auth = await requireUserAdmin(req);
	if (auth instanceof Response) return auth;

	const id = params?.id;
	if (!id) {
		return badRequest("User ID required");
	}

	const body = await req.json();
	const { newPassword } = body;

	if (!newPassword) {
		return badRequest("New password required");
	}

	if (newPassword.length < 8) {
		return badRequest("New password must be at least 8 characters");
	}

	const updated = await sql`
		UPDATE users SET password_hash = ${hashPassword(newPassword)}, updated_at = NOW()
		WHERE id = ${id}
		RETURNING id
	`;

	if (updated.length === 0) {
		return notFound("User not found");
	}

	return ok({ message: "Password updated" });
}

export async function deleteUser(
	req: Request,
	_url: URL,
	params?: Record<string, string>,
): Promise<Response> {
	const auth = await requireUserAdmin(req);
	if (auth instanceof Response) return auth;

	const id = params?.id;
	if (!id) {
		return badRequest("User ID required");
	}

	if (id === auth.user.id) {
		return badRequest("Cannot delete your own account");
	}

	const deleted = await sql`DELETE FROM users WHERE id = ${id} RETURNING id`;

	if (deleted.length === 0) {
		return notFound("User not found");
	}

	return noContent();
}
