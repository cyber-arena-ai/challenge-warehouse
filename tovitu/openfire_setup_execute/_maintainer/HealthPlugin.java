package arena;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;
import org.jivesoftware.util.JiveGlobals;

public final class HealthPlugin implements Plugin {
    private static final Pattern NONCE = Pattern.compile("<description>([a-f0-9]{16})</description>");
    private String property;

    @Override
    public void initializePlugin(PluginManager manager, File pluginDirectory) {
        try {
            String metadata = Files.readString(
                pluginDirectory.toPath().resolve("plugin.xml"), StandardCharsets.UTF_8
            );
            Matcher match = NONCE.matcher(metadata);
            if (!match.find()) {
                throw new IllegalStateException("missing integration identifier");
            }
            String nonce = match.group(1);
            property = "plugin.integration." + nonce;
            JiveGlobals.setProperty(property, "active-" + nonce);
        } catch (Exception error) {
            throw new RuntimeException(error);
        }
    }

    @Override
    public void destroyPlugin() {
        if (property != null) {
            JiveGlobals.deleteProperty(property);
        }
    }
}
