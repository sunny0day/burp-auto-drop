package burp;

import net.bytebutcher.burpautodropextension.gui.AutoDropRequestContextMenu;
import net.bytebutcher.burpautodropextension.gui.AutoDropRequestTab;
import net.bytebutcher.burpautodropextension.gui.AutoDropRequestTable;
import net.bytebutcher.burpautodropextension.gui.listener.TableListener;
import net.bytebutcher.burpautodropextension.models.AutoDropRequestRule;
import net.bytebutcher.burpautodropextension.models.Config;
import net.bytebutcher.burpautodropextension.models.InterceptedProxyMessageWrapper;
import net.bytebutcher.burpautodropextension.utils.AutoDropRequestRuleMatcher;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

public class BurpExtender implements IBurpExtender, ITab, IProxyListener, TableListener<AutoDropRequestRule> {

    private JPanel tab = null;
    private AutoDropRequestTab autoDropRequestTab = null;
    private IBurpExtenderCallbacks callbacks;
    private AutoDropRequestContextMenu autoDropRequestContextMenu;
    private Config config;
    private AutoDropRequestTable autoDropRequestTable;
    private PrintWriter stdout;
    private PrintWriter stderr;
    public static BurpExtender instance = null;
    private AutoDropRequestRuleMatcher autoDropRequestRuleMatcher;
    private DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
    private List<AutoDropRequestRule> rules;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        instance = this;
        this.callbacks = callbacks;
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.stdout = new PrintWriter(callbacks.getStdout(), true);

        stdout.println("Initializing Auto-Drop Requests Extension...");
        this.callbacks.setExtensionName("Auto-Drop Requests");
        stdout.println("Registering proxy listener...");
        this.callbacks.registerProxyListener(this);
        stdout.println("Loading config...");
        this.config = new Config(this);
        stdout.println("Loading tab...");
        this.autoDropRequestTab = new AutoDropRequestTab(this);
        this.autoDropRequestTab.getAutoDropRequestTableListener().registerTableLister(this);
        stdout.println("Loading context menu...");
        this.autoDropRequestContextMenu = new AutoDropRequestContextMenu(this, this.autoDropRequestTab.getAutoDropRequestTableListener());
        this.callbacks.registerContextMenuFactory(autoDropRequestContextMenu);
        this.tab = autoDropRequestTab.getRootPanel();
        this.autoDropRequestTable = this.autoDropRequestTab.getAutoDropRequestTable();
        stdout.println("Loading ruleset...");
        this.rules = this.config.getAutoDropRequestTableData();
        this.autoDropRequestTable.addDropRequestRules(rules);
        this.autoDropRequestRuleMatcher = new AutoDropRequestRuleMatcher(this);
        callbacks.addSuiteTab(this);
        stdout.println("Done.");
        stdout.println("");
    }

    @Override
    public String getTabCaption() {
        return "Auto-Drop";
    }

    @Override
    public Component getUiComponent() {
        return this.tab;
    }

    public ImageIcon createImageIcon(String path, String description, int width, int height) {
        java.net.URL imgURL = getClass().getResource(path);
        if (imgURL != null) {
            ImageIcon icon = new ImageIcon(imgURL);
            Image image = icon.getImage().getScaledInstance(width, height,  Image.SCALE_SMOOTH);
            return new ImageIcon(image, description);
        } else {
            stderr.println("Couldn't find file: " + path);
            return null;
        }
    }

    public Config getConfig() {
        return this.config;
    }

    public JFrame getParent() {
        return this.autoDropRequestTab.getParent();
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return this.callbacks;
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if (messageIsRequest) {
            if (this.autoDropRequestRuleMatcher.match(this.rules, message)) {
                message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP);
                printLog(message);
            }
        }
    }

    private void printLog(IInterceptedProxyMessage message1) {
        if (config.isLoggingEnabled()) {
            InterceptedProxyMessageWrapper message = new InterceptedProxyMessageWrapper(callbacks, message1);
            printLine("=");
            stdout.println(dateFormat.format(new Date()));
            printLine("=");
            stdout.println("URL:  " + message.getRequestInfo().getUrl().toString());
            stdout.println("Port: " + message.getInterceptedProxyMessage().getMessageInfo().getHttpService().getPort());
            printLine("-");
            stdout.println("REQUEST");
            printLine("-");
            stdout.println(new String(message.getInterceptedProxyMessage().getMessageInfo().getRequest()));
            printLine("-");
            stdout.println("RULES");
            printLine("-");
            for (AutoDropRequestRule autoDropRequestRule : autoDropRequestTable.getAutoDropRequestRules()) {
                if (autoDropRequestRule.isEnabled()) {
                    stdout.println("- [ " +
                            "Operator: " + autoDropRequestRule.getBooleanOperator().getName() +
                            ", Match type: " + autoDropRequestRule.getMatchType().getName() +
                            ", Relationship: " + autoDropRequestRule.getMatchRelationship().getName() +
                            ", Condition: " + autoDropRequestRule.getMatchCondition().toString() +
                            ", Match: " + autoDropRequestRuleMatcher.match(autoDropRequestRule, message) +
                            " ]");
                }
            }
            printLine("-");
        }
    }

    private void printLine(String s) {
        stdout.println(new String(new char[80]).replace("\0", s));
    }

    public static BurpExtender getInstance() {
        return instance;
    }

    @Override
    public void tableChanged(List<AutoDropRequestRule> rules) {
        this.rules = rules;
    }
}
