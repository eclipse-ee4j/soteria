package org.glassfish.soteria.cdi;

import static org.junit.Assert.*;
import org.junit.Test;

public class AnnotationELPProcessorTest {
  @Test
  public void shouldBuildExpectedMessageForNullOutcome() {
    String msg = AnnotationELPProcessor.buildNonBooleanOutcomeMessage(null, "abc");

    assertEquals("Expression abc should evaluate to boolean but evaluated to  null", msg);
  }

  @Test
  public void shouldBuildExpectedMessageForNonBooleanOutcome() {
    String msg = AnnotationELPProcessor.buildNonBooleanOutcomeMessage(1, "ijk");
  
    assertEquals("Expression ijk should evaluate to boolean but evaluated to class java.lang.Integer 1", msg);
  }

}

