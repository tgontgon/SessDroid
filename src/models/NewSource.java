package models;

import soot.SootMethod;

public class NewSource {
    private int keyIndex;
    private int valueIndex;
    private SootMethod wrapperMethod;

    public NewSource(int keyIndex, int valueIndex, SootMethod wrapperMethod){
        this.keyIndex = keyIndex;
        this.valueIndex = valueIndex;
        this.wrapperMethod = wrapperMethod;
    }

    public int getKeyIndex() {
        return keyIndex;
    }

    public int getValueIndex() {
        return valueIndex;
    }

    public SootMethod getWrapperMethod() {
        return wrapperMethod;
    }
}
