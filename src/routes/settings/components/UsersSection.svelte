<script lang="ts">
import { enhance } from "$app/forms";
import { formatDate, notifications } from "$lib";
import type { SubmitFunction } from "@sveltejs/kit";
import type { UserAccount } from "$lib";

const { users, currentUserId }: { users: UserAccount[]; currentUserId: string } = $props();

type Panel = { id: string; mode: "reset" | "confirm" };

let openPanel = $state<Panel | null>(null);

function isOpen(id: string, mode: Panel["mode"]): boolean {
	return openPanel?.id === id && openPanel.mode === mode;
}

function toggle(id: string, mode: Panel["mode"]) {
	openPanel = isOpen(id, mode) ? null : { id, mode };
}

function onResult(success: string, fallback: string): SubmitFunction {
	return () =>
		async ({ result, update }) => {
			if (result.type === "success") {
				notifications.success(success);
				openPanel = null;
				await update();
			} else if (result.type === "failure") {
				const error = result.data?.userError as string | undefined;
				notifications.error(error || fallback);
			}
		};
}
</script>

<section class="settings-section">
	<h3>users</h3>

	{#if users.length > 0}
		<div class="users-list">
			{#each users as account (account.id)}
				{@const isSelf = account.id === currentUserId}
				<div class="user-item" class:confirming={isOpen(account.id, "confirm")}>
					<div class="user-header">
						<span class="user-name">{account.username}</span>
						<span class="scope-badge">{account.role}</span>
						{#if isSelf}
							<span class="scope-badge">you</span>
						{/if}
					</div>
					<div class="user-meta">
						<span>{account.email}</span>
						<span>joined {formatDate(account.createdAt)}</span>
					</div>

					{#if isOpen(account.id, "confirm")}
						<p class="user-danger-warning">
							permanently delete {account.username}? this also removes their api keys,
							audit log entries and the invites they created. this cannot be undone.
						</p>
						<div class="user-danger-actions">
							<button type="button" class="btn sm" onclick={() => toggle(account.id, "confirm")}>
								cancel, keep {account.username}
							</button>
							<form method="POST" action="?/deleteUser" use:enhance={onResult("user deleted", "failed to delete user")}>
								<input type="hidden" name="userId" value={account.id} />
								<button type="submit" class="btn sm destructive">
									permanently delete {account.username}.
								</button>
							</form>
						</div>
					{:else}
						<div class="user-actions">
							{#if isSelf}
								<span class="user-hint">use the account tab to change your own password</span>
							{:else}
								<form method="POST" action="?/updateUserRole" use:enhance={onResult("role updated", "failed to update role")}>
									<input type="hidden" name="userId" value={account.id} />
									<input type="hidden" name="role" value={account.role === "admin" ? "viewer" : "admin"} />
									<button type="submit" class="btn sm">
										{account.role === "admin" ? "demote to viewer" : "promote to admin"}
									</button>
								</form>

								<button type="button" class="btn sm" onclick={() => toggle(account.id, "reset")}>
									{isOpen(account.id, "reset") ? "cancel" : "reset password"}
								</button>

								<button type="button" class="btn sm danger" onclick={() => toggle(account.id, "confirm")}>
									delete
								</button>
							{/if}
						</div>

						{#if isOpen(account.id, "reset")}
							<form method="POST" action="?/resetUserPassword" class="create-form user-reset-form" use:enhance={onResult("password reset", "failed to reset password")}>
								<div class="form-group">
									<label for="new-{account.id}">new password</label>
									<input id="new-{account.id}" type="password" name="newPassword" required minlength="8" autocomplete="new-password" />
								</div>
								<div class="form-group">
									<label for="confirm-{account.id}">confirm password</label>
									<input id="confirm-{account.id}" type="password" name="confirmPassword" required minlength="8" autocomplete="new-password" />
								</div>
								<input type="hidden" name="userId" value={account.id} />
								<div class="form-actions">
									<button type="submit" class="btn">set password</button>
								</div>
							</form>
						{/if}
					{/if}
				</div>
			{/each}
		</div>
	{:else}
		<p class="no-users">no users found</p>
	{/if}
</section>
