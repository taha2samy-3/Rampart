/** Full-page navigation (sign-in goes to the IdP, so it is a navigation, never a fetch). */
export function navigateTo(url: string): void {
  window.location.assign(url);
}
