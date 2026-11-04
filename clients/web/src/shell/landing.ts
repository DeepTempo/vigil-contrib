/** Home's gate; people without it land on Overview instead. */
export const HOME_PERM = 'ai_decisions.approve'

/** Day one setup's gate: building a baseline and going live are writes to findings. */
export const START_PERM = 'findings.write'

export const landingScreen = (hasPermission: (perm: string) => boolean): 'home' | 'overview' =>
  hasPermission(HOME_PERM) ? 'home' : 'overview'
