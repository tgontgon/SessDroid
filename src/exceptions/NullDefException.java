package exceptions;

import org.slf4j.Logger;
import utils.SessDroidLogger;

public class NullDefException extends RuntimeException{
    public NullDefException(){
        super();
    }
    public NullDefException(String message){
        SessDroidLogger.Info("WARN : " + message);
    }
}
