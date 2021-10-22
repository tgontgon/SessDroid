package exceptions;

public class UnzipApkException extends RuntimeException{
    public UnzipApkException(){super();}
    public UnzipApkException(String m){
        super(m);
    }
}
