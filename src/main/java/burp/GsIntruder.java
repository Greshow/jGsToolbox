package burp;

import burp.*;

public class GsIntruder implements IIntruderPayloadProcessor {
    private final GsUI gsUI;

    public GsIntruder(GsUI ui) {
        this.gsUI = ui;
    }

    @Override
    public String getProcessorName() {
        return "GsToolbox-Aes-encrypt"; // 你可以自定义这个名字
    }

    @Override
    public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue) {
        try {
            // 获取 UI 面板中的 AESPanel
            GsUI.AESPanel aesPanel = gsUI.getAESPanel();

            // 获取 key、iv、mode
            String key = aesPanel.getKey();
            String iv = aesPanel.getIv();
            String mode = aesPanel.getMode();

            // 使用 currentPayload 作为输入进行加密
            String input = new String(currentPayload);
            String encrypted = GsAes.encrypt(input, key, iv, mode);

            // 返回加密后的字节
            return encrypted.getBytes();
        } catch (Exception e) {
            // 错误处理，可以在负载中返回错误信息
            return ("[error] " + e.getMessage()).getBytes();
        }
    }
}
