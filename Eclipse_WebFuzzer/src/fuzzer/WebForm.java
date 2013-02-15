/**
 * 
 */
package fuzzer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.DomNodeList;
import com.gargoylesoftware.htmlunit.html.HtmlElement;
import com.gargoylesoftware.htmlunit.html.HtmlInput;
import com.gargoylesoftware.htmlunit.html.HtmlPasswordInput;
import com.gargoylesoftware.htmlunit.html.HtmlSubmitInput;

/**
 * Provides an interface for managing and interacting with information for a 
 * specific HTML input form
 * 
 * @author Eric Newman (edn6266)
 * @author Ross Kahn (rtk1865) 
 * @author Timothy Heard (tjh2430)
 */
public class WebForm
{
	private DomElement form;
	private DomNodeList<HtmlElement> inputs;
	private HtmlSubmitInput submitField;
	private HtmlInput usernameField;
	private HtmlPasswordInput passwordField;
	
	public WebForm(DomElement form)
	{
		this.form = form;
		this.inputs = form.getElementsByTagName("input");
		this.submitField = null;
		this.usernameField = null;
		this.passwordField = null;
		
		for(HtmlElement input: inputs)
		{
			String inputType = input.getAttribute("type");
			
			// TODO: Make sure that these casts do not cause any problems
			if(inputType == null)
			{
				continue;
			}
			else if(inputType.equals("password"))
			{
				passwordField = (HtmlPasswordInput) input;
			}
			else if(inputType.equals("submit"))
			{
				submitField = (HtmlSubmitInput) input;
			}
			else if(input.getId() != null && input.getId().contains("user"))
			{
				// TODO: Check is "contains("user") is the appropriate way to do this
				// (i.e. will it work?)
				usernameField = (HtmlInput) input;
			}
		}
	}
	
	public DomElement getForm()
	{
		return form;
	}

	public DomNodeList<HtmlElement> getInputs()
	{
		return inputs;
	}

	public HtmlInput getUsernameField()
	{
		return usernameField;
	}
	
	public HtmlPasswordInput getPasswordField()
	{
		return passwordField;
	}

	public HtmlSubmitInput getSubmitField()
	{
		return submitField;
	}

	public boolean requiresAuthentication()
	{
		return passwordField != null;
	}

	public Page submitAuthentication(String username, String password)
		throws IOException
	{
		if(usernameField != null && passwordField != null && submitField != null)
		{
			usernameField.setValueAttribute(username);
			passwordField.setValueAttribute(password);
			return submitField.click();
		}
		
		return null;
	}
	
	public static List<WebForm> toWebForms(DomNodeList<DomElement> forms)
	{
		List<WebForm> webForms = new ArrayList<WebForm>();
		
		for(DomElement form: forms)
		{
			webForms.add(new WebForm(form));
		}
		
		return webForms;
	}
}
