package arena;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;
import org.jivesoftware.util.JiveGlobals;

public final class ProofPlugin implements Plugin {
    private static final Pattern LOCATOR = Pattern.compile("<description>([a-f0-9]{24})</description>");
    private String property;

    @Override
    public void initializePlugin(PluginManager manager, File pluginDirectory) {
        try {
            String metadata = Files.readString(
                pluginDirectory.toPath().resolve("plugin.xml"), StandardCharsets.UTF_8
            );
            Matcher match = LOCATOR.matcher(metadata);
            if (!match.find()) {
                throw new IllegalStateException("missing execution locator");
            }
            String locator = match.group(1);
            Process process = new ProcessBuilder(
                "/usr/local/bin/openfire-proof", locator
            ).start();
            if (process.waitFor() != 0) {
                throw new IllegalStateException("execution proof failed");
            }
            String result = new String(
                process.getInputStream().readAllBytes(), StandardCharsets.UTF_8
            ).trim();
            property = "arena.execute.result." + locator;
            JiveGlobals.setProperty(property, result);
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
