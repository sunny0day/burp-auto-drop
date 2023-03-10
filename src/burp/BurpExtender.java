package burp;

import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author sunny0day
 */
public class BurpExtender implements IBurpExtender, IProxyListener, ITab 
{
	private JPanel mainPanel;
	private final JTextField dropHostsRegex = new JTextField("", 60);
	private IBurpExtenderCallbacks callbacks;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		callbacks.setExtensionName("Burp Auto Drop");
		callbacks.registerProxyListener(this);
		
		this.dropHostsRegex.setText(callbacks.loadExtensionSetting("dropHostsRegex"));
		this.dropHostsRegex.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent focusEvent) {
                super.focusLost(focusEvent);
                callbacks.saveExtensionSetting("dropHostsRegex", dropHostsRegex.getText());
            }
		});
		
		final JLabel regexLabel = new JLabel(
				"<html>"
				+ "Provide a regular expression for hosts that need to be dropped automatically in the text field below." 
				+ "<br>For example, use .*google.* to drop requests with an URL that contains the word google."
				+ "<br><br></html>"
		);
		regexLabel.putClientProperty("html.disable", null);
		
		// Main split pane
		mainPanel = new JPanel(new GridBagLayout());
		
		GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;

        mainPanel.add(regexLabel, gbc);
        gbc.gridy++;
        mainPanel.add(this.dropHostsRegex, gbc);
        gbc.gridx++;
		
		callbacks.addSuiteTab(BurpExtender.this);
	}

	@Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message)
    {
		// Only process requests
        if (messageIsRequest) {
        	IHttpRequestResponse messageInfo = message.getMessageInfo();
        	IRequestInfo requestInfo = this.callbacks.getHelpers().analyzeRequest(messageInfo);
        	        	
        	String regexValue = this.dropHostsRegex.getText();
        	
        	if (regexValue.length() > 0) {
        		Pattern regexPattern = Pattern.compile(regexValue);
                
                Matcher regexMatcher = regexPattern.matcher(requestInfo.getUrl().toString());
                if (regexMatcher.find()) {
                	message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP);
                	this.callbacks.printOutput("Dropping: " + requestInfo.getUrl());
                }
        	}
        }
    }

	@Override
	public String getTabCaption() {
		return "Auto Drop";
	}

	@Override
	public Component getUiComponent() {
		return this.mainPanel;
	}
}
