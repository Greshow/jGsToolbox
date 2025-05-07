package burp;

import javax.swing.*;
import java.awt.*;

public class BurpExtender implements IBurpExtender, ITab {
    private IBurpExtenderCallbacks callbacks;
    private GsUI gsUI;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName("GsToolbox");

        callbacks.registerContextMenuFactory(new GsContextMenu(callbacks));

        // 初始化 UI
        SwingUtilities.invokeLater(() -> {
            gsUI = new GsUI();

            // 添加 UI 到 Burp 的 tab 页
            callbacks.addSuiteTab(this);

            // 注册 Intruder Payload Processor
            GsUI.AESPanel aesPanel = gsUI.getAESPanel(); // 需要 getAESPanel() 方法
            GsIntruder gsIntruder = new GsIntruder(gsUI);
            callbacks.registerIntruderPayloadProcessor(gsIntruder);
        });
    }

    // ITab 接口方法
    @Override
    public String getTabCaption() {
        return "GsToolbox";
    }

    @Override
    public Component getUiComponent() {
        return gsUI.getMainPanel();
    }
}
