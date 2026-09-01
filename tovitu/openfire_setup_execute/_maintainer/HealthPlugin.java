package arena;

import java.io.File;

import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;

public final class HealthPlugin implements Plugin {
    @Override
    public void initializePlugin(PluginManager manager, File pluginDirectory) {
        // Installation and removal are the legitimate workflow being checked.
    }

    @Override
    public void destroyPlugin() {
    }
}
