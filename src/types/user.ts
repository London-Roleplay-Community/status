export const USER_ROLES = ["admin", "viewer"] as const;

export type UserRole = (typeof USER_ROLES)[number];

export interface User {
	id: string;
	username: string;
	email: string;
	role: UserRole;
	accessIds: string[];
}

export interface UserAccount {
	id: string;
	username: string;
	email: string;
	role: UserRole;
	createdAt: string;
}

export function isUserRole(value: string): value is UserRole {
	return (USER_ROLES as readonly string[]).includes(value);
}
