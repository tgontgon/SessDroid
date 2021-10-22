package utils;

import java.text.SimpleDateFormat;
import java.util.Calendar;

public class SessDroidLogger {
    public enum COLOR{RED, GREEN, BLUE};

    public static void Info(String m){
        System.err.println(prefix() + m);
    }
    public static void Log(String m){
        System.out.println(prefix() + m);
    }

    public static void Warn(String m){
        StackTraceElement i = new Throwable().getStackTrace()[1];
        System.err.println(prefix() + "[" + i.getClassName() + ":" + i.getMethodName() + "] "+ m);
    }

    public static void coloredLog(String m, COLOR c, boolean adopt){
        if(adopt){
            switch(c){
                case RED: System.out.print("\033[1;31m"); break;
                case GREEN: System.out.print("\033[32m"); break;
                case BLUE: System.out.print("\033[1;34m"); break;
                default: System.out.print("\033[0m"); break;
            }

            System.out.println(m);
            System.out.print("\033[0m");
        }else
            System.out.println(m);
    }


    private static String prefix() {
        return "[S][" + getCurrentTime() + "] ";
    }

    private static String getCurrentTime() {
        return (new SimpleDateFormat("HH:mm:ss").format(Calendar.getInstance().getTime()));
    }
}
