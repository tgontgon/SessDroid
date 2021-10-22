package models;

import soot.jimple.StringConstant;


public class SharedPreModel {
    public String getMetSig = "<android.content.SharedPreferences: java.lang.String getString(java.lang.String,java.lang.String)>";
    public StringConstant spLabel;
    public String putMethSig = "<android.content.SharedPreferences$Editor: android.content.SharedPreferences$Editor putString(java.lang.String,java.lang.String)>";

    public SharedPreModel(){}

    public SharedPreModel(StringConstant spLabel){
        this(null, spLabel, null);
    }

    public SharedPreModel(String getMeth, StringConstant label, String putMethSig){
        if (getMeth != null) {
            this.getMetSig = getMeth;
        }
        this.spLabel = label;
        if (putMethSig != null){
            this.putMethSig = putMethSig;
        }
    }

    @Override
    public String toString() {
        if (spLabel != null)
            return "SharedPreModel {" + spLabel.value + " / "
                + getMetSig + " / " + putMethSig + "}";
        return "EMPTY SPREMODEL";
    }

    public String toMethPairString(){
        return spLabel.value + getMetSig;
    }
}
