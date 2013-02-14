package fuzzer;

import java.io.IOException;
import java.net.MalformedURLException;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;

public class FuzzerMain {

	/**
	 * @param args
	 * @throws IOException 
	 * @throws MalformedURLException 
	 * @throws FailingHttpStatusCodeException 
	 */
	public static void main(String[] args) throws FailingHttpStatusCodeException, MalformedURLException, IOException {
		
		SiteInformationManager SIM = SiteInformationManager.initSiteInformationManager(args[0]);
		
		for(int i = 1; i < args.length; i++)
		{
			SIM.reconfigureRunAndReport(args[i]);
		}

	}

}
