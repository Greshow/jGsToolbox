package burp;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

public class GsContextMenu implements IContextMenuFactory {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;

    public GsContextMenu(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();

        // 创建主菜单 GsToolbox
        JMenu toolboxMenu = new JMenu("GsToolbox");

        // 子菜单：Unicode 解码
        JMenuItem decodeItem = new JMenuItem("Unicode-decode");
        decodeItem.addActionListener(e -> processSelectedText(invocation, true));

        // 子菜单：Unicode 编码
        JMenuItem encodeItem = new JMenuItem("Unicode-encode");
        encodeItem.addActionListener(e -> processSelectedText(invocation, false));

        toolboxMenu.add(decodeItem);
        toolboxMenu.add(encodeItem);

        // 添加 GsToolbox 菜单到右键
        menuItems.add(toolboxMenu);
        return menuItems;
    }

    private void processSelectedText(IContextMenuInvocation invocation, boolean decode) {
        IHttpRequestResponse[] selectedItems = invocation.getSelectedMessages();
        if (selectedItems == null || selectedItems.length == 0) {
            return;
        }

        int[] bounds = invocation.getSelectionBounds();
        if (bounds == null || bounds.length != 2) {
            return;
        }

        IHttpRequestResponse message = selectedItems[0];
        byte[] request = message.getRequest();
        String requestStr = new String(request);

        int start = bounds[0];
        int end = bounds[1];
        if (start < 0 || end > requestStr.length() || start >= end) {
            return;
        }

        String selectedText = requestStr.substring(start, end);
        String processedText = decode ? GsUnicode.decode(selectedText) : GsUnicode.encode(selectedText);

        String newRequestStr = requestStr.substring(0, start) + processedText + requestStr.substring(end);
        byte[] newRequest = newRequestStr.getBytes();
        message.setRequest(newRequest);
    }
}
