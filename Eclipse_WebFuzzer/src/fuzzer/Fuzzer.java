/**
 * 
 */
package fuzzer;

import java.io.IOException;
import java.net.MalformedURLException;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;

/**
 * Parses the command line arguments and performs web fuzzing using the 
 * configuration files with the provided file names.
 *
 * @author Eric Newman
 * @author Ross Kahn
 * @author Timothy Heard
 */
public class Fuzzer
{
	public static void main(String[] args)
	{
		if(args.length == 0)
		{
			System.out.println("Usage: java Fuzzer <the name of one or more " +
				"configuration files separated by spaces>");
			return;
		}
		
		try
		{
			SiteInformationManager informationManager = null;
			
			int index = 0;
			while(informationManager == null && index < args.length)
			{
				informationManager = 
						SiteInformationManager.loadConfigurationAndFuzz(args[index]);
				
				if(informationManager == null)
				{
					System.out.println("Unable to load configuration file at " + args[index]);
					return;
				}
			}
			
			if(informationManager == null)
			{
				// If none of the configuration files could be loaded then there
				// is nothing else to do
				return;
			}
			
			for(int i = 1; i < args.length; i++)
			{
				if(!informationManager.reconfigureAndFuzz(args[i]))
				{
					System.out.println("Unable to load configuration file at " + args[i]);
					continue;
				}
			}
			
			informationManager.writeReport(System.out);
		}
		catch (FailingHttpStatusCodeException e)
		{
			e.printStackTrace();
		} 
		catch (MalformedURLException e)
		{
			e.printStackTrace();
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
	}
}
