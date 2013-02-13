/**
 * 
 */
package fuzzer;

import java.util.ArrayList;
import java.util.List;

import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.DomNodeList;
import com.gargoylesoftware.htmlunit.html.HtmlElement;
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
	private List<HtmlSubmitInput> submitFields;
	private List<HtmlPasswordInput> passwordFields;
	
	public WebForm(DomElement form)
	{
		this.form = form;
		this.inputs = form.getElementsByTagName("input");
		this.submitFields = new ArrayList<HtmlSubmitInput>();
		this.passwordFields = new ArrayList<HtmlPasswordInput>();
		
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
				passwordFields.add((HtmlPasswordInput) input);
			}
			else if(inputType.equals("submit"))
			{
				submitFields.add((HtmlSubmitInput) input);
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

	public List<HtmlPasswordInput> getPasswordFields()
	{
		return passwordFields;
	}

	public List<HtmlSubmitInput> getSubmitFields()
	{
		return submitFields;
	}

	public boolean requiresAuthentication()
	{
		return !passwordFields.isEmpty();
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
