package app.revanced.patches.spotify.security.certificatepinningbypass

import app.revanced.patcher.data.BytecodeContext
import app.revanced.patcher.data.ResourceContext
import app.revanced.patcher.extensions.InstructionExtensions.addInstruction
import app.revanced.patcher.extensions.InstructionExtensions.addInstructions
import app.revanced.patcher.patch.BytecodePatch
import app.revanced.patcher.patch.PatchResult
import app.revanced.patcher.patch.PatchResultSuccess
import app.revanced.patcher.patch.ResourcePatch
import app.revanced.patcher.patch.annotations.CompatiblePackage
import app.revanced.patcher.patch.annotations.Patch
import app.revanced.patches.spotify.security.certificatepinningbypass.fingerprints.HostnameVerifierFingerprintPatch
import app.revanced.patches.spotify.security.certificatepinningbypass.fingerprints.TrustManagerFingerprintPatch
import org.w3c.dom.Element
import java.io.File

@Patch(
    name = "Certificate pinning bypass",
    description = "Bypasses certificate pinning, allowing HTTPS traffic inspection and modification.",
    dependencies = [
        TrustManagerFingerprintPatch::class,
        HostnameVerifierFingerprintPatch::class
    ],
    compatiblePackages = [
        CompatiblePackage(
            "com.spotify.music"
        )
    ]
)
class CertificatePinningBypassPatch : ResourcePatch {
    override fun execute(context: ResourceContext): PatchResult {
        // Add network security config XML
        val networkSecurityConfigXml = """
            <?xml version="1.0" encoding="utf-8"?>
            <network-security-config>
                <base-config cleartextTrafficPermitted="true">
                    <trust-anchors>
                        <certificates src="system" />
                        <certificates src="user" />
                    </trust-anchors>
                </base-config>
            </network-security-config>
        """.trimIndent()
        
        // Ensure the xml directory exists
        val xmlDir = File("${context.resDirectory}/xml")
        if (!xmlDir.exists()) xmlDir.mkdirs()
        
        // Write the network_security_config.xml file
        File("${context.resDirectory}/xml/network_security_config.xml").writeText(networkSecurityConfigXml)
        
        // Modify AndroidManifest.xml to include networkSecurityConfig attribute
        context.xmlEditor["AndroidManifest.xml"].use { editor ->
            val applicationElement = editor.file.documentElement.getElementsByTagName("application").item(0) as Element
            applicationElement.setAttribute("android:networkSecurityConfig", "@xml/network_security_config")
        }
        
        return PatchResultSuccess
    }
}
