import type { User, UserAccount, UserRole } from "../../../types";
import { request } from "./client";

export async function login(username: string, password: string): Promise<User> {
	const result = await request<{ user: User }>("/auth/login", {
		method: "POST",
		body: JSON.stringify({ username, password }),
	});
	return result.user;
}

export async function register(
	username: string,
	email: string,
	password: string,
	inviteCode?: string,
): Promise<User> {
	const result = await request<{ user: User }>("/auth/register", {
		method: "POST",
		body: JSON.stringify({ username, email, password, inviteCode }),
	});
	return result.user;
}

export async function isFirstUser(): Promise<boolean> {
	const result = await request<{ isFirstUser: boolean }>("/auth/first-user");
	return result.isFirstUser;
}

export async function getUserById(id: string, sessionId?: string): Promise<User | null> {
	try {
		const result = await request<{ user: User }>(`/auth/user/${id}`, { sessionId: sessionId || id });
		return result.user;
	} catch {
		return null;
	}
}

export async function changePassword(
	userId: string,
	currentPassword: string,
	newPassword: string,
	sessionId?: string,
): Promise<void> {
	await request(`/auth/user/${userId}/password`, {
		method: "PUT",
		body: JSON.stringify({ currentPassword, newPassword }),
		sessionId: sessionId || userId,
	});
}

export async function getUsers(sessionId: string): Promise<UserAccount[]> {
	const result = await request<{ users: UserAccount[] }>("/auth/users", { sessionId });
	return result.users;
}

export async function updateUserRole(
	userId: string,
	role: UserRole,
	sessionId: string,
): Promise<UserAccount> {
	const result = await request<{ user: UserAccount }>(`/auth/user/${userId}/role`, {
		method: "PUT",
		body: JSON.stringify({ role }),
		sessionId,
	});
	return result.user;
}

export async function resetUserPassword(
	userId: string,
	newPassword: string,
	sessionId: string,
): Promise<void> {
	await request(`/auth/user/${userId}/reset-password`, {
		method: "PUT",
		body: JSON.stringify({ newPassword }),
		sessionId,
	});
}

export async function deleteUser(userId: string, sessionId: string): Promise<void> {
	await request(`/auth/user/${userId}`, { method: "DELETE", sessionId });
}
