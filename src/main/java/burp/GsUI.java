package burp;

import javax.swing.*;
import java.awt.*;
import java.util.HashMap;

public class GsUI {
    private JPanel mainPanel;
    private JList<String> methodList;
    private JPanel rightPanel;
    private CardLayout cardLayout;
    private HashMap<String, JPanel> cryptoPanels;

    public GsUI() {
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // 左侧算法列表
        String[] methods = {"AES", "Unicode"};
        methodList = new JList<>(methods);
        methodList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        methodList.setSelectedIndex(0);
        methodList.setFixedCellWidth(120);

        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.setBorder(BorderFactory.createTitledBorder("Methods"));
        leftPanel.add(new JScrollPane(methodList), BorderLayout.CENTER);

        // 右侧算法面板，使用CardLayout切换
        cardLayout = new CardLayout();
        rightPanel = new JPanel(cardLayout);
        rightPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        cryptoPanels = new HashMap<>();
        cryptoPanels.put("AES", new AESPanel());
        cryptoPanels.put("Unicode", new UnicodePanel());

        for (String method : methods) {
            rightPanel.add(cryptoPanels.get(method), method);
        }

        // 监听切换选项
        methodList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                String selected = methodList.getSelectedValue();
                cardLayout.show(rightPanel, selected);
            }
        });

        // 左右分栏
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel);
        splitPane.setDividerLocation(150);
        splitPane.setResizeWeight(0); // 右侧占满空间

        mainPanel.add(splitPane, BorderLayout.CENTER);
    }

    public JPanel getMainPanel() {
        return mainPanel;
    }
    public AESPanel getAESPanel() {
        return (AESPanel) cryptoPanels.get("AES");
    }


    // -------------------------------
    // AES 加解密面板
    // -------------------------------
    class AESPanel extends JPanel {
        private final JTextArea inputArea = createTextArea();
        private final JTextArea outputArea = createTextArea();
        private final JTextField keyField = new JTextField(32);
        private final JTextField ivField = new JTextField(32);
        private final JComboBox<String> modeBox = new JComboBox<>(new String[] {
                "ECB", "CBC", "CTR", "CFB", "OFB", "GCM"
        });
        private final JComboBox<String> paddingBox = new JComboBox<>(new String[]{
                "PKCS5Padding", "PKCS7Padding", "NoPadding", "ZeroPadding"
        });
        private final JComboBox<String> keySizeBox = new JComboBox<>(new String[] {
                "128", "192", "256" // 这表示密钥位数为 128-bit、192-bit 和 256-bit
        });
        private final JButton encryptButton = new JButton("Encrypt");
        private final JButton decryptButton = new JButton("Decrypt");

        public String getKey() {
            return keyField.getText().trim();
        }

        public String getIv() {
            return ivField.getText().trim();
        }

        public String getMode() {
            return "AES/" + (String) modeBox.getSelectedItem() + "/" + (String) paddingBox.getSelectedItem() + "/" + (String) keySizeBox.getSelectedItem();
        }

        AESPanel() {
            setLayout(new GridBagLayout());
            GridBagConstraints gbc = createGbc();

            // 输入输出区域
            gbc.gridx = 0;
            gbc.gridy = 0;
            gbc.gridwidth = 2;
            add(createScrollPane(inputArea, "Input"), gbc);

            gbc.gridy = 1;
            add(createScrollPane(outputArea, "Output"), gbc);

            // 控制区
            gbc.gridy = 2;
            gbc.gridwidth = 1;
            gbc.weighty = 0;

            JPanel controlPanel = new JPanel(new GridBagLayout());
            GridBagConstraints c = new GridBagConstraints();
            c.insets = new Insets(2, 2, 2, 2);
            c.fill = GridBagConstraints.HORIZONTAL;

            c.gridx = 0; c.gridy = 0;
            controlPanel.add(new JLabel(" Key (base64): "), c);
            c.gridx = 1;
            controlPanel.add(keyField, c);
            c.gridx = 2;
            controlPanel.add(new JLabel(" IV (base64): "), c);
            c.gridx = 3;
            controlPanel.add(ivField, c);
            c.gridx = 4;
            controlPanel.add(new JLabel(" Mode:"), c);
            c.gridx = 5;
            controlPanel.add(modeBox, c);
            c.gridx = 6;
            controlPanel.add(paddingBox, c);
            c.gridx = 7;
            controlPanel.add(keySizeBox, c);

            add(controlPanel, gbc);

            // 按钮区
            gbc.gridy = 3;
            gbc.gridwidth = 2;
            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));
            buttonPanel.add(encryptButton);
            buttonPanel.add(decryptButton);
            add(buttonPanel, gbc);

            // 按钮逻辑绑定（后期接入 GsAes 类）
            encryptButton.addActionListener(e -> encrypt());
            decryptButton.addActionListener(e -> decrypt());
        }

        private void encrypt() {
            try {
                String input = inputArea.getText();
                String key = getKey();
                String ivHex = getIv();
                String mode = getMode();
                String result = GsAes.encrypt(input, key, ivHex, mode);
                outputArea.setText(result);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Encryption failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }

        private void decrypt() {
            try {
                String input = inputArea.getText();
                String key = getKey();
                String ivHex = getIv();
                String mode = getMode();
                String result = GsAes.decrypt(input, key, ivHex, mode);
                outputArea.setText(result);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Decryption failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }

    }

    // -------------------------------
    // Unicode 编解码面板
    // -------------------------------
    class UnicodePanel extends JPanel {
        private final JTextArea inputArea = createTextArea();
        private final JTextArea outputArea = createTextArea();
        private final JButton encodeButton = new JButton("Encode");
        private final JButton decodeButton = new JButton("Decode");

        UnicodePanel() {
            setLayout(new GridBagLayout());
            GridBagConstraints gbc = createGbc();

            gbc.gridx = 0;
            gbc.gridy = 0;
            gbc.gridwidth = 2;
            add(createScrollPane(inputArea, "Input"), gbc);

            gbc.gridy = 1;
            add(createScrollPane(outputArea, "Output"), gbc);

            gbc.gridy = 2;
            gbc.weighty = 0;
            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));
            buttonPanel.add(encodeButton);
            buttonPanel.add(decodeButton);
            add(buttonPanel, gbc);

            // 绑定事件（后期接入 GsUnicode 类）
            encodeButton.addActionListener(e -> encodeUnicode());
            decodeButton.addActionListener(e -> decodeUnicode());
        }

        private void encodeUnicode() {
            try {
                String input = inputArea.getText();
                String result = GsUnicode.encode(input);
                outputArea.setText(result);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Encoding failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }

        private void decodeUnicode() {
            try {
                String input = inputArea.getText();
                String result = GsUnicode.decode(input);
                outputArea.setText(result);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Decoding failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }

    }

    // -------------------------------
    // 公共辅助方法
    // -------------------------------
    private static JTextArea createTextArea() {
        JTextArea area = new JTextArea(10, 40);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        return area;
    }

    private static JScrollPane createScrollPane(JComponent comp, String title) {
        JScrollPane scroll = new JScrollPane(comp);
        scroll.setBorder(BorderFactory.createTitledBorder(title));
        return scroll;
    }

    private static GridBagConstraints createGbc() {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        return gbc;
    }
}
