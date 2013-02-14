package fuzzer;

/**
 * POJO (plain old Java object) representation of fuzzer application settings. 
 * 
 * @author Eric Newman (edn6266)
 * @author Ross Kahn (rtk1865) 
 * @author Timothy Heard (tjh2430)
 */
public class FuzzerData {
	
	private static FuzzerData self;
	
	private boolean SEARCH_COMPLETE = true;
	private boolean passwordGuessing = false;
	private int TIME_GAP = 0;
	private String username, password, dataFileName, authenticationSuccessString; 
	
	public FuzzerData(){
		
	}
	
	public static FuzzerData getInstance(){
		if(self == null){
			self = new FuzzerData();
		}
		
		return self;
	}
	
	public void setCompleteness(boolean complete){
		SEARCH_COMPLETE = complete;
	}
	
	public void setTimeGap(int gap){
		TIME_GAP = gap;
	}
	
	public float timeGap(){
		return TIME_GAP;
	}
	
	public boolean completeness(){
		return SEARCH_COMPLETE;
	}
	
	public String toString(){
		String result = "CURRENT SYSTEM OPTIONS:\n";
		String complete = SEARCH_COMPLETE ? "Complete" : "Random";
		result += "\tSearch Completeness => " + complete + "\n";
		result += "\tTime Gap => " + this.TIME_GAP + "\n";
		return result;
		
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getDataFileName() {
		return dataFileName;
	}

	public void setDataFileName(String dataFileName) {
		this.dataFileName = dataFileName;
	}

	public boolean passwordGuessingIsOn() {
		return passwordGuessing;
	}

	public void setPasswordGuessing(boolean passwordGuessing) {
		this.passwordGuessing = passwordGuessing;
	}

	public String getAuthenticationSuccessString() {
		return authenticationSuccessString;
	}

	public void setAuthenticationSuccessString(
			String authenticationSuccessString) {
		this.authenticationSuccessString = authenticationSuccessString;
	}
}
