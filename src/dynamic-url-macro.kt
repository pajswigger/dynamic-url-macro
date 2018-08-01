package burp

import org.json.JSONObject
import org.json.JSONTokener
import java.net.URI
import java.util.*
import java.util.regex.Pattern

const val actionNamePrefix = "Dynamic URL Macro: "

class BurpExtender: IBurpExtender, IExtensionStateListener {
    private val timer = Timer()

    companion object {
        lateinit var callbacks: IBurpExtenderCallbacks
    }

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        Companion.callbacks = callbacks
        callbacks.setExtensionName("Dynamic URL Macro")
        callbacks.registerExtensionStateListener(this)
        timer.scheduleAtFixedRate(SyncMacros(), 0, 10000)
    }

    override fun extensionUnloaded() {
        timer.cancel()
    }
}


fun loadMacros(): MutableMap<String, JSONObject> {
    var macrosJson = BurpExtender.callbacks.saveConfigAsJson("project_options.sessions.macros.macros")
    val root = JSONObject(JSONTokener(macrosJson))
    val macros = root.getJSONObject("project_options")
            .getJSONObject("sessions")
            .getJSONObject("macros")
            .getJSONArray("macros")

    val macroMap = hashMapOf<String, JSONObject>()
    for(i in 0 until macros.length()) {
        val macro = macros.getJSONObject(i)
        macroMap[macro.getString("description")] = macro
    }
    return macroMap
}


class SyncMacros: TimerTask() {
    override fun run() {
        val macros = loadMacros()
        for(action in BurpExtender.callbacks.sessionHandlingActions) {
            if(macros.remove((action as SessionHandlingAction).macroName) == null) {
                BurpExtender.callbacks.removeSessionHandlingAction(action)
            }
        }

        for(macroName in macros.keys) {
            // TODO: only register if macro has at least one POST?
            BurpExtender.callbacks.registerSessionHandlingAction(SessionHandlingAction(macroName))
        }
    }
}

val actionRegex = Pattern.compile("<form.*?action\\s*?=\\s*?['\"](.*?)['\"]", Pattern.CASE_INSENSITIVE)!!

class SessionHandlingAction(val macroName: String): ISessionHandlingAction {
    override val actionName = actionNamePrefix + macroName

    override fun performAction(currentRequest: IHttpRequestResponse, macroItems: Array<IHttpRequestResponse>?) {
        val macro = loadMacros()[macroName]!!
        val items = macro.getJSONArray("items")
        var actionUri: URI? = null
        for(i in 0 until items.length()) {
            val item = items.getJSONObject(i)
            val uri = URI(item.getString("url"))
            var request = item.getString("request").toByteArray(Charsets.ISO_8859_1)

            val method = item.getString("method")
            if(method == "POST" && actionUri != null) {
                val requestInfo = BurpExtender.callbacks.helpers.analyzeRequest(request)
                var actionString = actionUri.path
                if(actionUri.query != null) {
                    actionString += "?${actionUri.query}"
                }
                val headers = requestInfo.headers.toMutableList()
                headers[0] = "$method $actionString HTTP/1.1"

                request = BurpExtender.callbacks.helpers.buildHttpMessage(headers, request.copyOfRange(requestInfo.bodyOffset, request.size))
            }

            val response = BurpExtender.callbacks.makeHttpRequest(uri.host, uri.port, uri.scheme == "https", request)
            val responseString = String(response, Charsets.ISO_8859_1)
            val matcher = actionRegex.matcher(responseString)
            if(matcher.find()) {
                actionUri = uri.resolve(matcher.group(1))
            }
            else {
                actionUri = null
            }
        }
    }
}
