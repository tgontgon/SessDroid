package models;

import javafx.util.Pair;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;

import java.io.*;
import java.util.HashSet;
import java.util.Set;

/**
 * the top analysis class, import sources
 */
public class SourcesParser{
    private Set<String> sourcesSigs;
    private Set<NewSource> newSources;
    private Set<String> newSourceSigs;

    public SourcesParser(String sourcesFile)throws IOException{
        this(loadSourcesExpr(sourcesFile));
    }

    public SourcesParser(Set<String> sourcesSigs){
        this.sourcesSigs = sourcesSigs;
        this.newSources = new HashSet<>();
    }

    private static Set<String> loadSourcesExpr(String sourcesFile) throws IOException {
        if (!new File(sourcesFile).exists()){
            throw new RuntimeException(sourcesFile + " Can't find source file!");
        }
        FileReader fr = new FileReader(sourcesFile);
        return loadSourcesExpr(fr);
    }

    public void addNewSource(NewSource newSource){
        newSources.add(newSource);
    }

    private static Set<String> loadSourcesExpr(Reader reader) throws IOException {

        Set<String> sources = new HashSet<>();
        try(BufferedReader bufferedReader = new BufferedReader(reader)){
            String line;
            while((line = bufferedReader.readLine()) != null){
                sources.add(line.trim());
            }
        }
        return sources;
    }


    public void printInputSourceFile(){
        System.out.println("**************************source file**************************");
        for (String str : sourcesSigs){
            System.out.println(str);
        }
        System.out.println();
    }
    /**
     * @param source String type to add
     */
    public void addSource(String source){
        this.sourcesSigs.add(source);
    }

    /**
     * determine the input unit whether contains
     * @param unit input
     * @return if contains return true
     */
    public boolean isContainSourceExpr(Unit unit){

        if (this.sourcesSigs.isEmpty()) {
            throw new RuntimeException("The sourceExprsFile has no sources!");
        }
        for (String source : this.sourcesSigs){
            if (unit.toString().toLowerCase().contains(source.toLowerCase())){
                return true;
            }
        }
        return false;
    }

    public NewSource containsNewSource(InvokeExpr ie){
        SootMethod callee = ie.getMethod();

        for (NewSource newSource : newSources){
            if (newSource.getWrapperMethod().equals(callee)){
                return newSource;
            }
        }
        return null;
    }

    /**
     * get sourcesExprs
     * @return Set
     */
    public Set<String> getInputSourcesExprs() {
        return sourcesSigs;
    }
}

