package burp;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class GsUnicode {
    public static String encode(String input) {
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            sb.append(String.format("\\u%04x", (int) c));
        }
        return sb.toString();
    }

    public static String decode(String input) {
        Pattern p = Pattern.compile("\\\\u([0-9a-fA-F]{4})");
        Matcher m = p.matcher(input);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            char ch = (char) Integer.parseInt(m.group(1), 16);
            m.appendReplacement(sb, Character.toString(ch));
        }
        m.appendTail(sb);
        return sb.toString();
    }
}
