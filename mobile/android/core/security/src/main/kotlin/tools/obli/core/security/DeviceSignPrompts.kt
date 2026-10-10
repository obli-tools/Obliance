package tools.obli.core.security

/**
 * Localised texts of the fingerprint prompt (`deviceKeys.prompt.*`,
 * `deviceKeys.secondStep`), read from the app's resources by the host.
 */
class SignPromptTexts(
    /** « Double authentification, pour cette action uniquement » */
    val description: String,
    /** « Deuxième validation : double authentification » (after a T2/T3 local biometric) */
    val secondStep: String,
    /** « Utiliser un code »: the negative button (the device credential is never offered). */
    val useCode: String,
    /** « {{action}} sur {{count}} appareils » */
    val bulk: (action: String, count: Int) -> String,
    /** « Connexion à {{server}} » */
    val login: (server: String) -> String,
)

/**
 * The texts of the system biometric prompt, built natively from the action
 * and the SERVER's challenge: title = the action and its
 * target, subtitle = « serveur › tenant » (the server always named, the
 * tenant as the challenge names it — display only, the binding covers it),
 * description = what the signature is for. Every value is cleaned of control
 * characters and shortened: a server string never shapes the dialog.
 */
object DeviceSignPrompts {
    const val MAX_LENGTH = 120

    fun stepUp(spec: ActionSpec, request: DeviceSignRequest, texts: SignPromptTexts): SignPrompt {
        val title = if (request.count > 1) {
            texts.bulk(clean(spec.title), request.count)
        } else {
            listOf(spec.title, spec.target).map(::clean).filter { it.isNotEmpty() }.joinToString(" ")
        }
        val tenant = request.tenantName?.let(::clean)?.takeIf { it.isNotEmpty() }
        val subtitle = when (val server = spec.serverName?.let(::clean)?.takeIf { it.isNotEmpty() }) {
            null -> clean(spec.scope).takeIf { it.isNotEmpty() }
            else -> listOfNotNull(server, tenant).joinToString(" › ")
        }
        val description = if (spec.tier == Tier.T2 || spec.tier == Tier.T3) texts.secondStep else texts.description
        return SignPrompt(clean(title), subtitle, description, texts.useCode)
    }

    /** Sign-in with the fingerprint: « Connexion à Obliance Prod », the username below. */
    fun login(serverName: String, username: String, texts: SignPromptTexts): SignPrompt =
        SignPrompt(clean(texts.login(clean(serverName))), clean(username).takeIf { it.isNotEmpty() }, null, texts.useCode)

    /**
     * No control character and no format character (a server string is never
     * trusted): ISO controls and the line / paragraph separators become
     * spaces; Unicode format characters (bidi embeddings and overrides
     * U+202A–202E, isolates U+2066–2069, marks U+200E/200F, zero-width
     * characters…) are dropped, so a name can neither break the layout nor be
     * visually reordered. At most [MAX_LENGTH] characters.
     */
    fun clean(value: String): String {
        val flat = StringBuilder(value.length)
        var i = 0
        while (i < value.length) {
            val cp = value.codePointAt(i)
            i += Character.charCount(cp)
            when {
                Character.isISOControl(cp) || cp == 0x2028 || cp == 0x2029 -> flat.append(' ')
                Character.getType(cp) == Character.FORMAT.toInt() -> Unit
                else -> flat.appendCodePoint(cp)
            }
        }
        val trimmed = flat.toString().trim().replace(Regex("\\s+"), " ")
        return if (trimmed.length <= MAX_LENGTH) trimmed else trimmed.take(MAX_LENGTH - 1).trimEnd() + "…"
    }
}
