package core;

import java.io.IOException;

import test.Curupira1Test;
import test.LetterSoupTest;
import test.MarvinTest;

public class Main {
    public static void main(String[] args) throws IOException {
	Curupira1Test.test();
	MarvinTest.test();
	LetterSoupTest.test();
    }
}
