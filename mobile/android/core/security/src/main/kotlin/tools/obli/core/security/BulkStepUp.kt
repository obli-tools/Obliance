package tools.obli.core.security

import java.util.UUID
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import tools.obli.core.network.ApiOutcome
import tools.obli.core.network.DeviceChallenge
import tools.obli.core.network.DeviceError
import tools.obli.core.network.DeviceKeyStatus
import tools.obli.core.network.FailureKind

/**
 * What a bulk run did, per target, in the order of the targets: the server's
 * last answer for each target that was sent, and the targets never sent with
 * a proof because the user cancelled ([skipped]).
 */
data class BulkReport<K, T>(
    val outcomes: Map<K, ApiOutcome<T>>,
    val skipped: List<K> = emptyList(),
) {
    val succeeded: List<K> get() = outcomes.filterValues { it is ApiOutcome.Ok || it is ApiOutcome.Accepted }.keys.toList()
    val failed: Map<K, ApiOutcome<T>> get() = outcomes.filterValues { it !is ApiOutcome.Ok && it !is ApiOutcome.Accepted }

    /** The value of each target that went through. */
    fun values(): Map<K, T> = outcomes.mapNotNull { (k, o) ->
        when (o) {
            is ApiOutcome.Ok -> k to o.value
            is ApiOutcome.Accepted -> k to o.value
            else -> null
        }
    }.toMap()
}

/**
 * One fingerprint for a loop of "one request per target" with the SAME action:
 *
 * 1. **First pass**: every request carries `deviceBulkId` (one UUID per run,
 *    kept in `extra`, removed by the server before the binding). Each answer
 *    is a success (the action ran) or a step-up 401 whose challenge carries
 *    that bulk id.
 * 2. **One prompt** (« Redémarrer sur 12 appareils · Obliance Prod › ACME »):
 *    one signature covers up to 50 challenges (`count = N`), which must share
 *    the action, the tenant and the bulk id ([DeviceSignRequest.stepUp]
 *    checks it; the server checks it again, and the 60 s spread).
 * 3. **Second pass**: each waiting request is sent again, SAME body, with the
 *    SAME assertion; the server consumes only its own challenge.
 *
 * A request whose challenge expired meanwhile gets one more signature round
 * (2 rounds at most, like a single action). Anything else — no challenge, a
 * refused assertion, « Utiliser un code », a locked-out biometric — falls
 * back on ONE 2FA sheet for the rest of the loop (code, + password on a bound
 * session), the code then sent with each remaining request (the server
 * accepts it again in the same session). A tenant that differs from the
 * action's ends the run `Blocked(TENANT_CHANGED)` before any signature; an
 * expired session ends it at once (never replayed). The password lives only
 * in this run.
 */
internal class BulkStepUp(
    private val prompter: ActionPrompter,
    private val deviceKeys: DeviceKeyResolver?,
    private val newBulkId: () -> String = { UUID.randomUUID().toString() },
    /** Session tenant and server name per origin, for specs that do not set them. */
    private val sessionInfo: ActionSessionInfo? = null,
) {
    private class Waiting<K>(val target: K, val step: ApiOutcome.StepUpRequired)

    suspend fun <K, T> run(spec: ActionSpec, targets: List<K>, call: suspend (target: K, extra: JsonObject) -> ApiOutcome<T>): ActionResult<BulkReport<K, T>> {
        val bulk = buildJsonObject { put(ActionRunner.BULK_ID, JsonPrimitive(newBulkId())) }
        val results = LinkedHashMap<K, ApiOutcome<T>>()

        // 1. First pass, no proof.
        var waiting = mutableListOf<Waiting<K>>()
        for (target in targets.distinct()) {
            when (val out = call(target, bulk)) {
                ApiOutcome.SessionExpired -> return expired()
                is ApiOutcome.StepUpRequired -> waiting += Waiting(target, out)
                else -> results[target] = out
            }
        }
        if (waiting.isEmpty()) return ActionResult.Done(report(targets, results))

        // 2–3. Fingerprint rounds.
        val byCode = mutableListOf<Waiting<K>>()
        var rounds = 0
        while (waiting.isNotEmpty() && rounds < ActionRunner.MAX_SIGN_ATTEMPTS) {
            val next = mutableListOf<Waiting<K>>()
            val (signable, others) = waiting.partition { challengeOf(it.step) != null && keyFor(it.step) != null }
            byCode += others
            if (signable.isEmpty()) break
            val changed = signable.firstOrNull { w ->
                val expected = sessionInfo.expectedTenant(spec, w.step.origin!!)
                challengeOf(w.step)!!.tenantId.let { it != null && expected != null && it != expected }
            }
            if (changed != null) {
                try {
                    sessionInfo?.tenantChanged(changed.step.origin!!)
                } catch (_: RuntimeException) {
                    // Informative: the run is refused either way.
                }
                return ActionResult.Blocked(ActionRunner.TENANT_CHANGED)
            }
            rounds++
            for (chunk in signable.chunked(DeviceProofPayload.MAX_CHALLENGES)) {
                val origin = chunk.first().step.origin!!
                val record = keyFor(chunk.first().step)!!
                val request = try {
                    require(chunk.all { it.step.origin == origin && keyFor(it.step) == record })
                    DeviceSignRequest.stepUp(origin, record, chunk.map { challengeOf(it.step)!! })
                } catch (_: IllegalArgumentException) {
                    null
                }
                if (request == null) {
                    byCode += chunk
                    continue
                }
                when (val signed = prompter.signStepUp(sessionInfo.promptSpec(spec, origin).copy(targetCount = chunk.size), request)) {
                    is SignResult.Signed -> {
                        val extra = buildJsonObject {
                            bulk.forEach { (k, v) -> put(k, v) }
                            put(DeviceAssertion.FIELD, request.assertion(signed.der).toJson())
                        }
                        for (w in chunk) {
                            when (val out = call(w.target, extra)) {
                                ApiOutcome.SessionExpired -> return expired()
                                is ApiOutcome.StepUpRequired -> {
                                    val device = out.device
                                    if (device?.error == DeviceError.CHALLENGE_EXPIRED && challengeOf(out) != null) next += Waiting(w.target, out) else byCode += Waiting(w.target, out)
                                }
                                is ApiOutcome.StepUpRejected -> byCode += w
                                else -> results[w.target] = out
                            }
                        }
                    }
                    SignResult.UseCode, SignResult.LockedOut, is SignResult.Unavailable -> byCode += chunk
                    SignResult.Cancelled -> return cancelled(targets, results, chunk.map { it.target } + byCode.map { it.target } + next.map { it.target } + remainingAfter(signable, chunk))
                    SignResult.Invalidated -> {
                        prompter.deviceKeyInvalidated(request.origin, request.record.keyId)
                        return ActionResult.SessionExpired
                    }
                }
            }
            waiting = next
        }
        byCode += waiting

        // Fallback: ONE code for the rest of the loop.
        return withCode(spec, targets, results, byCode, bulk, call)
    }

    private suspend fun <K, T> withCode(
        spec: ActionSpec,
        targets: List<K>,
        results: LinkedHashMap<K, ApiOutcome<T>>,
        byCode: List<Waiting<K>>,
        bulk: JsonObject,
        call: suspend (K, JsonObject) -> ApiOutcome<T>,
    ): ActionResult<BulkReport<K, T>> {
        val remaining = ArrayDeque(byCode.map { it.target }.distinct().filter { it !in results })
        if (remaining.isEmpty()) return ActionResult.Done(report(targets, results))
        var step: ApiOutcome.StepUpRequired? = byCode.lastOrNull()?.step
        var wrong = false
        var used = false
        var attempts = 0
        var accepted = false
        // The Obligate re-authentication (SSO device keys) lasts 5 min on the server and a wrong code does
        // not consume it: once per loop, again only when the server asks again (a new step-up).
        var reauthDone = false
        while (remaining.isNotEmpty()) {
            if (attempts >= ActionRunner.MAX_CODE_ATTEMPTS) {
                remaining.forEach { results[it] = ApiOutcome.StepUpRejected(used) }
                break
            }
            val options = TwoFactorOptions(
                trustIpAllowed = step?.trustIpAllowed ?: true,
                passwordRequired = step?.codeRequiresPassword ?: false,
                reauthRequired = step?.codeRequiresReauth ?: false,
                previousCodeUsed = used,
            )
            if (options.reauthRequired && !reauthDone) {
                val origin = step?.origin ?: return cancelled(targets, results, remaining.toList())
                when (val r = prompter.reauthenticateSso(origin, spec)) {
                    SsoReauthResult.Success -> reauthDone = true
                    SsoReauthResult.Cancelled -> return cancelled(targets, results, remaining.toList())
                    is SsoReauthResult.Failed -> return if (r.endsSession) expired() else reauthFailed(targets, results, remaining.toList())
                }
            }
            val answer = prompter.askTwoFactor(spec, step?.currentIp, wrong, options) ?: return cancelled(targets, results, remaining.toList())
            attempts++
            val password = answer.password?.takeIf { options.passwordRequired && it.isNotEmpty() }
            val extra = buildJsonObject {
                bulk.forEach { (k, v) -> put(k, v) }
                put(ActionRunner.CODE, JsonPrimitive(answer.code.trim()))
                if (password != null) put(ActionRunner.PASSWORD, JsonPrimitive(password))
                if (answer.trustIp && options.trustIpAllowed && !options.passwordRequired) put(ActionRunner.TRUST_IP, JsonPrimitive(true))
            }
            wrong = false
            used = false
            while (remaining.isNotEmpty()) {
                val target = remaining.first()
                when (val out = call(target, extra)) {
                    ApiOutcome.SessionExpired -> return expired()
                    is ApiOutcome.StepUpRejected -> {
                        wrong = true
                        used = out.codeUsed
                        break
                    }
                    is ApiOutcome.StepUpRequired -> {
                        // The server wants another kind of code now (bound session: password + code),
                        // or a new re-authentication (its 5 min window ended): asked again.
                        step = out
                        reauthDone = false
                        break
                    }
                    else -> {
                        remaining.removeFirst()
                        results[target] = out
                        if (out is ApiOutcome.Ok || out is ApiOutcome.Accepted) accepted = true
                    }
                }
            }
        }
        if (accepted) codeWasAccepted(spec, step)
        return ActionResult.Done(report(targets, results))
    }

    /** The first-2FA proposal (A3) after a code on a session without device part, as in [ActionRunner]. */
    private fun codeWasAccepted(spec: ActionSpec, step: ApiOutcome.StepUpRequired?) {
        if (step == null || step.device != null) return
        val origin = step.origin ?: return
        val known = try {
            deviceKeys?.keyFor(origin)
        } catch (_: RuntimeException) {
            null
        }
        if (known != null) return
        try {
            prompter.codeAccepted(spec, origin)
        } catch (_: RuntimeException) {
            // Informative only.
        }
    }

    /** The step-up's challenge when it may be signed: an ACTIVE key status, not refused, of the client's origin. */
    private fun challengeOf(step: ApiOutcome.StepUpRequired): DeviceChallenge? {
        val device = step.device ?: return null
        if (device.status != DeviceKeyStatus.ACTIVE) return null
        if (device.error == DeviceError.INVALID_ASSERTION || device.error == DeviceError.OTHER) return null
        return device.challenge
    }

    /** This phone's key of (origin, user of the session), when the challenge names it. */
    private fun keyFor(step: ApiOutcome.StepUpRequired): DeviceKeyRecord? {
        val origin = step.origin ?: return null
        val challenge = challengeOf(step) ?: return null
        val record = try {
            deviceKeys?.keyFor(origin)
        } catch (_: RuntimeException) {
            null
        } ?: return null
        if (record.origin != origin || record.userId != challenge.userId || record.keyId != challenge.keyId) return null
        return record
    }

    private fun <K> remainingAfter(all: List<Waiting<K>>, chunk: List<Waiting<K>>): List<K> {
        val at = all.indexOf(chunk.last())
        return all.drop(at + 1).map { it.target }
    }

    private suspend fun expired(): ActionResult<Nothing> {
        prompter.sessionExpired()
        return ActionResult.SessionExpired
    }

    /** Cancelled by the user: nothing went through → [ActionResult.Cancelled]; else the report with [notSent] skipped. */
    private fun <K, T> cancelled(targets: List<K>, results: LinkedHashMap<K, ApiOutcome<T>>, notSent: List<K>): ActionResult<BulkReport<K, T>> {
        val done = results.values.any { it is ApiOutcome.Ok || it is ApiOutcome.Accepted || it is ApiOutcome.PendingApproval }
        if (!done) return ActionResult.Cancelled
        val skipped = notSent.distinct().filter { it !in results }
        return ActionResult.Done(report(targets, results, skipped))
    }

    /**
     * The Obligate re-authentication the code needed was refused (SSO device keys):
     * reported, never a silent cancel. Nothing went through →
     * `Blocked(SSO_REAUTH_FAILED)`; else the report, the targets not sent
     * failing with that reason.
     */
    private fun <K, T> reauthFailed(targets: List<K>, results: LinkedHashMap<K, ApiOutcome<T>>, notSent: List<K>): ActionResult<BulkReport<K, T>> {
        val done = results.values.any { it is ApiOutcome.Ok || it is ApiOutcome.Accepted || it is ApiOutcome.PendingApproval }
        if (!done) return ActionResult.Blocked(ActionRunner.SSO_REAUTH_FAILED)
        notSent.distinct().filter { it !in results }.forEach { results[it] = ApiOutcome.Failure(null, FailureKind.CLIENT, ActionRunner.SSO_REAUTH_FAILED) }
        return ActionResult.Done(report(targets, results))
    }

    private fun <K, T> report(targets: List<K>, results: Map<K, ApiOutcome<T>>, skipped: List<K> = emptyList()): BulkReport<K, T> {
        val ordered = LinkedHashMap<K, ApiOutcome<T>>()
        for (t in targets.distinct()) results[t]?.let { ordered[t] = it }
        return BulkReport(ordered, skipped)
    }
}
