/*
 * *****************************************************************************
 * Copyright (C) 2014-2025 Dennis Sheirer
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 * ****************************************************************************
 */

package io.github.dsheirer.channel.state;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Tests for State enum transitions and StateMachine behavior related to the ENCRYPTED state.
 */
public class StateMachineEncryptedTest
{
    @Test
    public void testCallCanTransitionToEncrypted()
    {
        assertTrue(State.CALL.canChangeTo(State.ENCRYPTED),
            "CALL state should allow transition to ENCRYPTED");
    }

    @Test
    public void testActiveCanTransitionToEncrypted()
    {
        assertTrue(State.ACTIVE.canChangeTo(State.ENCRYPTED),
            "ACTIVE state should allow transition to ENCRYPTED");
    }

    @Test
    public void testDataCanTransitionToEncrypted()
    {
        assertTrue(State.DATA.canChangeTo(State.ENCRYPTED),
            "DATA state should allow transition to ENCRYPTED");
    }

    @Test
    public void testEncryptedCanTransitionToFade()
    {
        assertTrue(State.ENCRYPTED.canChangeTo(State.FADE),
            "ENCRYPTED state should allow transition to FADE");
    }

    @Test
    public void testEncryptedCanTransitionToTeardown()
    {
        assertTrue(State.ENCRYPTED.canChangeTo(State.TEARDOWN),
            "ENCRYPTED state should allow transition to TEARDOWN");
    }

    @Test
    public void testEncryptedCanTransitionToReset()
    {
        assertTrue(State.ENCRYPTED.canChangeTo(State.RESET),
            "ENCRYPTED state should allow transition to RESET");
    }

    @Test
    public void testEncryptedCannotTransitionToCall()
    {
        assertFalse(State.ENCRYPTED.canChangeTo(State.CALL),
            "ENCRYPTED state should NOT transition to CALL (encryption is sticky)");
    }

    @Test
    public void testEncryptedIsInActiveStates()
    {
        assertTrue(State.SINGLE_CHANNEL_ACTIVE_STATES.contains(State.ENCRYPTED),
            "ENCRYPTED should be in SINGLE_CHANNEL_ACTIVE_STATES");
        assertTrue(State.MULTI_CHANNEL_ACTIVE_STATES.contains(State.ENCRYPTED),
            "ENCRYPTED should be in MULTI_CHANNEL_ACTIVE_STATES");
    }

    @Test
    public void testStateMachineTransitionToEncrypted()
    {
        StateMachine sm = new StateMachine(0, State.SINGLE_CHANNEL_ACTIVE_STATES);
        assertEquals(State.IDLE, sm.getState(), "Initial state should be IDLE");

        sm.setState(State.CALL);
        assertEquals(State.CALL, sm.getState(), "Should transition to CALL");

        sm.setState(State.ENCRYPTED);
        assertEquals(State.ENCRYPTED, sm.getState(), "Should transition from CALL to ENCRYPTED");
    }

    @Test
    public void testStateMachineEncryptedContinuationUpdatesFadeTimeout()
    {
        StateMachine sm = new StateMachine(0, State.SINGLE_CHANNEL_ACTIVE_STATES);
        sm.setFadeTimeoutBufferMilliseconds(5000);

        sm.setState(State.CALL);
        sm.setState(State.ENCRYPTED);
        assertEquals(State.ENCRYPTED, sm.getState());

        long timeoutBefore = sm.getFadeTimeout();

        //Small delay to ensure time advances
        try { Thread.sleep(10); } catch(InterruptedException ignored) {}

        //Same-state continuation should update the fade timeout
        sm.setState(State.ENCRYPTED);
        assertEquals(State.ENCRYPTED, sm.getState(), "State should remain ENCRYPTED");
        assertTrue(sm.getFadeTimeout() >= timeoutBefore,
            "Fade timeout should be updated on same-state continuation");
    }

    @Test
    public void testStateMachineCallRejectedWhenEncrypted()
    {
        StateMachine sm = new StateMachine(0, State.SINGLE_CHANNEL_ACTIVE_STATES);
        sm.setState(State.CALL);
        sm.setState(State.ENCRYPTED);
        assertEquals(State.ENCRYPTED, sm.getState());

        //CALL transition should be rejected when in ENCRYPTED state
        sm.setState(State.CALL);
        assertEquals(State.ENCRYPTED, sm.getState(),
            "CALL transition should be rejected when in ENCRYPTED state");
    }

    @Test
    public void testEncryptedDisplayValue()
    {
        assertEquals("ENCRYPTED", State.ENCRYPTED.getDisplayValue(),
            "ENCRYPTED state should have display value 'ENCRYPTED'");
    }
}
