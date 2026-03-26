# Baryon ESPer
### A PSP Baryon Sweeper port for ESP32 — easier, more accessible PSP unbricking
*Original Baryon Sweeper by khubik2 — ESP32 port guide*

---

## What is this?

Baryon ESPer lets you use a cheap ESP32 microcontroller to replicate the PSP Baryon Sweeper tool, which puts a PSP into **Service Mode** — the first step to recovering a bricked console.

---

## What you'll need

| Item | Notes |
|---|---|
| ESP32 board + USB cable | Any model should work |
| Working PSP battery | Must hold a charge |
| Breadboard + jumper wires | Or soldering setup if you prefer |
| Computer with Arduino IDE | Free download at arduino.cc |
| 10kΩ resistor | |
| Diode | Any standard signal diode with an orange band and black band (e.g. 1N4148) |
| Magic Memory Stick | **Not covered in this guide** — recommended tool: DC-ARK4 |

> ⚠️ **The Magic Memory Stick is required to actually unbrick your PSP.** This guide only covers getting into Service Mode. Prepare your Magic Memory Stick separately before proceeding.

---

## Step 1 — Wiring the circuit

The goal of this step is to build the following circuit:

<img width="512" height="512" alt="Final_Circuit_Diagram" src="https://github.com/user-attachments/assets/83558f36-383d-49c5-9a82-75bc09364509" />
<img width="512" height="512" alt="Final_Circuit_Picutre" src="https://github.com/user-attachments/assets/ef78a2c7-5c17-458d-a9ff-b598dfbec593" />

### Wiring steps

1. **Prepare four wires on the ESP32**, connected to:
   - `GND`
   - `3.3V`
   - `Pin 4`
   - `Pin 5`

2. **Add the pull-up resistor and diode:**
   - Bridge `Pin 5` to `3.3V` using the **10kΩ resistor**
   - Connect the **anode** (orange band side) of the diode to `Pin 5`
   - Connect the **cathode** (black band side) of the diode to `Pin 4`

3. **Make the PSP battery terminal connector:**
   Connect `Pin 5` to the **middle pin** of the PSP's battery terminal.

   > 💡 **Tip:** It helps to make a 3-pin connector by pushing three wires into a small piece of wood or plastic so they stay evenly spaced and can plug into the PSP terminal cleanly. Connect the middle pin to the ESP's `Pin 5`.

4. **Connect the battery positive (`+`):**
   Connect the **right pin** of the PSP's battery terminal to the **`+` terminal of your PSP battery**.

   > 💡 **Tip:** It's recommended to make a separate 2-pin connector for the battery side, and a 3-pin connector for the PSP side.

5. **Connect ground:**
   Link the ESP32's `GND` to **both**:
   - The **left pin** of the PSP's battery terminal
   - The **`−` terminal** of your PSP battery

> ⚠️ **Double-check polarity before connecting the battery.** Reversed polarity can damage your PSP or ESP32.

---

## Step 2 — Flashing the ESP32

1. **Download** the `esper.ino` file from this GitHub repository.

2. **Open Arduino IDE**, create a new sketch, and paste the contents of `esper.ino` into it.

3. **Select your board and port:**
   - In the Board Manager, install **ESP32 by Espressif Systems** if you haven't already.
   - Select your ESP32 model and the correct COM port (Arduino IDE usually detects it automatically).

   > 💡 You may need to install additional drivers (e.g. CP210x or CH340) depending on your ESP32 model.

4. **Enable USB CDC on Boot:**
   Go to `Tools` → `USB CDC On Boot` → `Enabled`

5. **Upload the sketch:**
   Click the upload button and wait for Arduino IDE to compile and flash.

   > 💡 You can also edit the `TX` and `RX` pin numbers in the code to match your own wiring — just make sure the pins you choose are not already used by your ESP32 model.

6. **Done!** Your Baryon ESPer is ready. You can open the Serial Monitor in Arduino IDE to watch the output (availability depends on your ESP32 model, but it's not required).

---

## Step 3 — Entering Service Mode

> ⚠️ Follow these steps in order. Connecting things in the wrong sequence can cause issues.

1. **Power the ESP32** via its USB port (connect it to your PC or a USB wall adapter).
   You should see a **red LED** on the ESP32. If it's off, the board isn't getting power — check your USB connection.

2. **Connect your battery connector** to the PSP battery.
   Make sure the polarity is correct! Standard Dupont connectors can be pushed directly into the battery terminal if they fit.

3. **On the PSP:**
   - Plug in the **DC power cable**
   - Insert your **Magic Memory Stick**

4. **Connect the 3-pin PSP terminal connector.**
   Push it firmly into the PSP's battery terminal and make sure it holds well.

5. **Wait 1–3 seconds.** The PSP should boot into **Service Mode**.

### Troubleshooting

| Problem | Try this |
|---|---|
| PSP doesn't enter Service Mode | Check all connections, especially the 3-pin terminal |
| Still not working | In the code, change `SERIAL_8E1` to `SERIAL_8E2` in the `Serial1.begin(...)` line — ESP32s can be picky about serial modes |

```cpp
// Change this:
Serial1.begin(19200, SERIAL_8E1, PSP_RX_PIN, PSP_TX_PIN);

// To this:
Serial1.begin(19200, SERIAL_8E2, PSP_RX_PIN, PSP_TX_PIN);
```

---

## Credits

- **[Baryon Sweeper](https://github.com/khubik2/pysweeper)** — original tool by [khubik2](https://github.com/khubik2)
- **Baryon ESPer** — ESP32 port and guide by Nyxef
