import ghidra.app.script.GhidraScript;
import lief.Utils;
import lief.ghidra.core.NativeBridge;

public class LiefVersionInfoScript extends GhidraScript {
    @Override
    protected void run() throws Exception {
        print("LIEF");
        NativeBridge.init();
        if (!NativeBridge.isLoaded()) {
            printerr("Can't load native bridge");
            throw new Exception();
        }
        print("LIEF Extended: " + Utils.isExtended());
        if (Utils.isExtended()) {
            Utils.Version version = Utils.getExtendedVersion();
            print(String.format(
                "Extended Version: %d.%d.%d.%d",
                version.major(), version.minor(), version.patch(), version.id()
            ));
            print(String.format(
                "Extended Version:\n%s\n",
                Utils.getExtendedVersionInfo()
            ));
        } else {
            Utils.Version version = Utils.getVersion();
            print(String.format(
                "Version: %d.%d.%d",
                version.major(), version.minor(), version.patch()
            ));
        }

    }
}
