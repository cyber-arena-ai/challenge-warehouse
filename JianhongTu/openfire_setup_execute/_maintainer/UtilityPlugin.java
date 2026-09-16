package org.igniterealtime.openfire.plugin.utility;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;
import org.jivesoftware.util.JiveGlobals;

public final class UtilityPlugin implements Plugin {
    private static final String EXPECTED_STATUS =
        "00000000000000000000000000000000";
    private String property;

    @Override
    public void initializePlugin(PluginManager manager, File pluginDirectory) {
        String canonical = pluginDirectory.getName();
        if (!canonical.matches("[a-z][a-z0-9-]{7,47}")) {
            throw new IllegalStateException("invalid plugin identifier");
        }
        Properties configuration = new Properties();
        File resource = new File(pluginDirectory, "resources/utility.properties");
        try (InputStream stream = new FileInputStream(resource)) {
            configuration.load(stream);
        } catch (IOException error) {
            throw new IllegalStateException("plugin configuration unavailable", error);
        }
        String status = configuration.getProperty("status", "");
        if (!status.matches("[a-f0-9]{32}") || !status.equals(EXPECTED_STATUS)) {
            throw new IllegalStateException("invalid plugin status");
        }
        property = "plugin." + canonical + ".status";
        JiveGlobals.setProperty(property, status);
    }

    @Override
    public void destroyPlugin() {
        if (property != null) {
            JiveGlobals.deleteProperty(property);
        }
    }
}
