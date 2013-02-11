/**
 * 
 */
package fuzzer;

/**
 * @author Ross
 *
 */
public class FuzzerData {
	
	private static FuzzerData self;
	
	private boolean SEARCH_COMPLETE = true;
	private int TIME_GAP = 0;
	
	private FuzzerData(){
		
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
}
