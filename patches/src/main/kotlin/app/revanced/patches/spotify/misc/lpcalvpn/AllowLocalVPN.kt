/*

ReVanced Patch: Accept All User Certificates


---

This module injects a networkSecurityConfig into the manifest,

provides the XML config resource, and no-ops any X509TrustManager checks.

Build instructions:

1. Add this module to your ReVanced build (include in build.gradle & settings.gradle).



2. Compile and package as a .jar for use with revanced-cli's -b flag. */




package com.example.revanced.patches;

import com.revanced.gateway.; import com.revanced.patcher.Patcher; import com.revanced.patcher.transformers.; import com.revanced.patcher.transformers.manifest.ManifestEditTransformer; import com.revanced.patcher.transformers.resources.ResourceInjector; import com.revanced.patcher.transformers.smali.SmaliAsmTransformer; import org.objectweb.asm.tree.*;

public class AcceptUserCerts implements PatchModule {

@Override
public void register(Patcher patcher) {
    patcher
        // 1. Inject networkSecurityConfig attribute into Application tag
        .transform(new ManifestEditTransformer()
            .addApplicationAttribute("android:networkSecurityConfig", "@xml/network_security_config"))
        // 2. Add the network_security_config.xml resource
        .transform(new ResourceInjector()
            .addXml("res/xml/network_security_config.xml",
                "<network-security-config>\n" +
                "  <base-config>\n" +
                "    <trust-anchors>\n" +
                "      <certificates src=\"system\"/>\n" +
                "      <certificates src=\"user\"/>\n" +
                "    </trust-anchors>\n" +
                "  </base-config>\n" +
                "</network-security-config>"))
        // 3. No-op X509TrustManager.checkServerTrusted
        .transform(new SmaliAsmTransformer()
            .filter((classNode, methodNode) ->
                /* find any method named checkServerTrusted with two args */
                methodNode.name.equals("checkServerTrusted") 
                    && methodNode.desc.equals("([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V"))
            .replaceMethodWithEmpty())
        // 4. No-op HostnameVerifier.verify(...) => return true
        .transform(new SmaliAsmTransformer()
            .filter((classNode, methodNode) ->
                classNode.name.endsWith("HostnameVerifier")
                    && methodNode.name.equals("verify")
                    && methodNode.desc.equals("(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z"))
            .injectBefore("return-0",
                new InsnListBuilder()
                    .iconst(1)
                    .insn(1 /* IRETURN */)
                    .build()));
}

@Override
public String getName() {
    return "accept_user_certs";
}

@Override
public String getDescription() {
    return "Allow user-installed CAs and disable all certificate checks";
}

@Override
public String[] getTargets() {
    return new String[]{"app"};
}

}

