/*
 * LPC1768 Digital Clock, Alarm, Stopwatch and Countdown Timer
 * Keil uVision / LPC17xx CMSIS
 *
 * LCD (external, 4-bit mode):
 *   D4-D7 = P0.23-P0.26
 *   RS    = P0.27
 *   EN    = P0.28
 *   R/W   = GND
 *
 * Matrix keypad (external):
 *   Rows R0-R3 = P2.10-P2.13 (outputs, one row HIGH at a time)
 *   Cols C0-C3 = P1.23-P1.26 (inputs with internal pull-downs)
 *
 * Buzzer (via FRC CNA / CNA5):
 *   P0.11, active-high (audible alarm/timer/stopwatch notifications)
 *
 * RTC:
 *   Uses LPC1768 internal RTC alarm interrupt. If RTC is stopped or its
 *   calendar values are invalid, default date/time is loaded from compile time.
 */

#include <LPC17xx.h>
#include <stdio.h>

/* ---------------- Pin definitions ---------------- */
#define LCD_DATA_MASK       (0x0FUL << 23)
#define LCD_RS              (1UL << 27)
#define LCD_EN              (1UL << 28)
#define LCD_PIN_MASK        (0x3FUL << 23)

#define KEYPAD_ROW_MASK     (0x0FUL << 10)
#define KEYPAD_COL_MASK     (0x0FUL << 23)

/* Active buzzer: FRC CNA -> CNA5 pin 8 = P0.11 (active-high).
 * Kept separate from LCD P0.23-P0.28, keypad pins and ADC4 P1.30. */
#define BUZZER_PIN          (1UL << 11)

/* ---------------- Global state ---------------- */
unsigned int i;
unsigned int temp1, temp2;
unsigned int flag1, flag2;
unsigned int lcd_init_single_nibble = 0;

volatile unsigned int stopwatch_seconds = 0;
volatile unsigned int remaining_seconds = 0;
volatile unsigned int stopwatch_running = 0;
volatile unsigned int countdown_running = 0;

volatile unsigned int alarm_event = 0;
volatile unsigned int timer_complete_event = 0;
volatile unsigned int stopwatch_stop_event = 0;

volatile unsigned int alarm_enabled = 0;
volatile unsigned int notification_active = 0;
volatile unsigned int notification_type = 0;
volatile unsigned int return_home_requested = 0;

unsigned int alarm_hour = 0;
unsigned int alarm_minute = 0;

unsigned char keypad_key;

/* ---------------- Advanced alarm additions (existing pins retained) ---------------- */
#define ADC4_MAX_VALUE       4095UL
#define ADC4_SAMPLE_COUNT    16U
#define DIAG_NOT_RUN         0U
#define DIAG_PASS            1U
#define DIAG_FAIL            2U
#define DIAG_SKIPPED         3U

volatile unsigned int math_challenge_active = 0U;
volatile unsigned int math_expected_answer = 0U;
volatile unsigned int math_answer_digit = 0U;
volatile unsigned int math_answer_entered = 0U;

volatile unsigned int feature_timer_ticks = 0U;
volatile unsigned int feature_pwm_phase = 0U;
volatile unsigned int feature_pwm_ready = 0U;

unsigned int alarm_max_intensity = 60U;
unsigned int alarm_mode = 2U;       /* 1=Gentle, 2=Normal, 3=Critical buzzer pattern */
unsigned int alarm_intensity_candidate = 60U;
unsigned int alarm_mode_candidate = 2U;
unsigned int adc4_last_reading = 0U;
unsigned int adc4_last_valid = 0U;
unsigned int math_a = 0U, math_b = 0U, math_operator = 0U;
unsigned int math_prng_state = 0xA341316CUL;
unsigned int feature_pattern_tick = 0U;
unsigned int feature_breath_level = 0U;
int feature_breath_direction = 1;
unsigned int diag_rtc = DIAG_NOT_RUN;
unsigned int diag_adc = DIAG_NOT_RUN;
unsigned int diag_pwm = DIAG_NOT_RUN;
unsigned int diag_timer = DIAG_NOT_RUN;
unsigned int diag_keypad = DIAG_NOT_RUN;

void feature_adc_init(void);
unsigned int feature_adc_read_average(void);
void feature_timer1_init(void);
void feature_update_led_pattern(void); /* retained name; now updates buzzer duty/pattern */
void feature_generate_challenge(void);
void feature_display_challenge(void);
void feature_handle_challenge_key(unsigned char key);
void feature_alarm_configuration(unsigned int *intensity, unsigned int *mode);
void feature_diagnostics(void);
unsigned int feature_random_bounded(unsigned int bound);

unsigned char keypad[4][4] = {
    {'1', '2', '3', 'A'},
    {'4', '5', '6', 'B'},
    {'7', '8', '9', 'C'},
    {'*', '0', '#', 'D'}
};

/* Notification type values */
#define NOTE_NONE       0
#define NOTE_ALARM      1
#define NOTE_COUNTDOWN  2
#define NOTE_STOPWATCH  3

/* ---------------- Delay functions ---------------- */
void delay_short(void)
{
    volatile unsigned int n;
    for (n = 0; n < 500; n++);
}

void delay_long(void)
{
    volatile unsigned int n;
    for (n = 0; n < 50000; n++);
}

void keypad_delay(void)
{
    volatile unsigned int n;
    for (n = 0; n < 10000; n++);
}

/* ---------------- LCD driver ---------------- */
void port_write(void)
{
    LPC_GPIO0->FIOCLR = LCD_DATA_MASK;
    LPC_GPIO0->FIOSET = temp2;

    if (flag1 == 0)
        LPC_GPIO0->FIOCLR = LCD_RS;
    else
        LPC_GPIO0->FIOSET = LCD_RS;

    LPC_GPIO0->FIOSET = LCD_EN;
    delay_short();
    LPC_GPIO0->FIOCLR = LCD_EN;
    delay_long();
}

void LCD_write(void)
{
    temp2 = (temp1 & 0xF0U) << 19;
    port_write();

    if (lcd_init_single_nibble == 0)
    {
        temp2 = (temp1 & 0x0FU) << 23;
        port_write();
    }
}

void lcd_command(unsigned int command)
{
    flag1 = 0;
    temp1 = command;
    LCD_write();

    if (command == 0x01 || command == 0x02)
        delay_long();
}

void lcd_data(unsigned char data)
{
    flag1 = 1;
    temp1 = data;
    LCD_write();
}

void lcd_string(char *text)
{
    while (*text != '\0')
    {
        lcd_data((unsigned char)*text);
        text++;
    }
}

void lcd_clear(void)
{
    lcd_command(0x01);
    delay_long();
}

void lcd_goto(unsigned int row, unsigned int col)
{
    if (row == 0)
        lcd_command(0x80U + col);
    else
        lcd_command(0xC0U + col);
}

void lcd_init(void)
{
    unsigned int startup_delay;
    unsigned int commands_ini[] =
        {0x30, 0x30, 0x30, 0x20, 0x28, 0x0C, 0x06, 0x01, 0x80};

    for (startup_delay = 0; startup_delay < 10; startup_delay++)
        delay_long();

    flag1 = 0;
    lcd_init_single_nibble = 1;
    for (i = 0; i < 4; i++)
    {
        temp1 = commands_ini[i];
        LCD_write();
        delay_long();
    }

    lcd_init_single_nibble = 0;
    for (i = 4; i < 9; i++)
    {
        temp1 = commands_ini[i];
        LCD_write();
        if (temp1 == 0x01)
            delay_long();
        else
            delay_short();
    }

    lcd_clear();
}

/* ---------------- Keypad driver ---------------- */
unsigned char keypad_scan(void)
{
    unsigned int row, col;
    unsigned long int row_bit;
    unsigned long int col_value;

    for (row = 0; row < 4; row++)
    {
        LPC_GPIO2->FIOCLR = KEYPAD_ROW_MASK;

        row_bit = 1UL << (10 + row);
        LPC_GPIO2->FIOSET = row_bit;

        keypad_delay();

        col_value = (LPC_GPIO1->FIOPIN >> 23) & 0x0FUL;

        if (col_value != 0)
        {
            if (col_value & 0x01UL)
                col = 0;
            else if (col_value & 0x02UL)
                col = 1;
            else if (col_value & 0x04UL)
                col = 2;
            else if (col_value & 0x08UL)
                col = 3;
            else
                continue;

            LPC_GPIO2->FIOCLR = KEYPAD_ROW_MASK;

            if (keypad[row][col] == '*')
                return 'E';
            if (keypad[row][col] == '#')
                return 'F';

            return keypad[row][col];
        }
    }

    LPC_GPIO2->FIOCLR = KEYPAD_ROW_MASK;
    return 0;
}

void service_events(void);
void display_home(void);
void dismiss_notification(void);

unsigned char get_key(void)
{
    unsigned char key;

    while (1)
    {
        service_events();

        if (notification_active)
        {
            while (notification_active)
            {
                key = keypad_scan();
                if (key != 0)
                {
                    keypad_delay();
                    if (keypad_scan() == key)
                    {
                        while (keypad_scan() != 0)
                            delay_short();

                        if (notification_type == NOTE_ALARM && math_challenge_active)
                        {
                            feature_handle_challenge_key(key);
                            if (!notification_active)
                                return 'N';
                        }
                        else if (key == 'E')
                        {
                            dismiss_notification();
                            /* Return special character 'N' so menus know to redraw, not exit */
                            return 'N';
                        }
                    }
                }
            }
        }

        key = keypad_scan();
        if (key != 0)
        {
            keypad_delay();
            if (keypad_scan() == key)
            {
                while (keypad_scan() != 0)
                {
                    service_events();
                    delay_short();

                    if (notification_active)
                        break;
                }

                if (notification_active)
                    continue;

                keypad_delay();
                return key;
            }
        }
    }
}

int read_four_digits(char *digits)
{
    unsigned int count = 0;
    unsigned char key;

    digits[0] = '\0';
    digits[1] = '\0';
    digits[2] = '\0';
    digits[3] = '\0';
    digits[4] = '\0';

    while (count < 4)
    {
        key = get_key();

        /* If an alarm happens during digit entry, safely abort and return home */
        if (key == 'N' || key == 'E' || return_home_requested)
            return 0;

        if (key >= '0' && key <= '9')
        {
            digits[count] = (char)key;
            lcd_data(key);
            count++;
        }
    }

    digits[4] = '\0';
    return 1;
}


/* ---------------- Advanced alarm feature implementation ---------------- */
void feature_adc_init(void)
{
    /* AD0.4 = P1.30, function 3. Do not alter P1.31 / AD0.5. */
    LPC_SC->PCONP |= (1UL << 12);
    LPC_PINCON->PINSEL3 &= ~(3UL << 28);
    LPC_PINCON->PINSEL3 |=  (3UL << 28);
}

unsigned int feature_adc_read_average(void)
{
    unsigned int n, timeout, raw;
    unsigned long sum = 0UL;

    for (n = 0U; n < ADC4_SAMPLE_COUNT; n++)
    {
        LPC_ADC->ADCR = (1UL << 4) | (1UL << 21) | (1UL << 24);
        timeout = 100000UL;
        while ((LPC_ADC->ADGDR & (1UL << 31)) == 0UL && timeout > 0U)
            timeout--;

        if (timeout == 0U)
            return adc4_last_valid; /* Safe fallback on conversion timeout. */

        raw = (unsigned int)((LPC_ADC->ADGDR >> 4) & 0x0FFFUL);
        sum += raw;
    }

    adc4_last_reading = (unsigned int)(sum / ADC4_SAMPLE_COUNT);
    adc4_last_valid = adc4_last_reading;
    return adc4_last_reading;
}

/*
 * Timer1 is dedicated to software PWM/cadence on the P0.11 buzzer GPIO.
 * Timer0 remains the original 1-second stopwatch/countdown timer.
 * No pin mapping or external connection is changed.
 */
void feature_timer1_init(void)
{
    LPC_SC->PCONP |= (1UL << 2);
    LPC_SC->PCLKSEL0 &= ~(3UL << 4);
    LPC_SC->PCLKSEL0 |=  (1UL << 4); /* Timer1 clock = CCLK. */

    LPC_TIM1->TCR = 0x02;
    LPC_TIM1->CTCR = 0x00;
    LPC_TIM1->PR = (SystemCoreClock / 1000000UL) - 1UL;
    LPC_TIM1->MR0 = 999UL;            /* 1 ms timer interrupt. */
    LPC_TIM1->MCR = 0x03;
    LPC_TIM1->IR = 0xFF;

    NVIC_ClearPendingIRQ(TIMER1_IRQn);
    NVIC_EnableIRQ(TIMER1_IRQn);
    LPC_TIM1->TCR = 0x01;
    feature_pwm_ready = 1U;
}

void TIMER1_IRQHandler(void)
{
    if (LPC_TIM1->IR & 0x01UL)
    {
        LPC_TIM1->IR = 0x01;
        feature_timer_ticks++;

        if (notification_active && notification_type == NOTE_ALARM &&
            feature_pwm_ready)
        {
            feature_pwm_phase++;
            if (feature_pwm_phase >= 100U)
                feature_pwm_phase = 0U;

            if (feature_pwm_phase < alarm_intensity_candidate)
                LPC_GPIO0->FIOSET = BUZZER_PIN;
            else
                LPC_GPIO0->FIOCLR = BUZZER_PIN;
        }
        else if (notification_active)
        {
            /* Audible reminder for timer/stopwatch notices: 250 ms ON / 250 ms OFF. */
            feature_pwm_phase++;
            if (feature_pwm_phase >= 500U)
                feature_pwm_phase = 0U;
            if (feature_pwm_phase < 250U)
                LPC_GPIO0->FIOSET = BUZZER_PIN;
            else
                LPC_GPIO0->FIOCLR = BUZZER_PIN;
        }
        else
        {
            LPC_GPIO0->FIOCLR = BUZZER_PIN;
            feature_pwm_phase = 0U;
        }
    }
}

/* Small PRNG for challenge variation; rejection sampling avoids modulo bias. */
static unsigned int feature_random_u32(void)
{
    unsigned int x = math_prng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    math_prng_state = x;
    return x;
}

unsigned int feature_random_bounded(unsigned int bound)
{
    unsigned int x, threshold;
    if (bound <= 1U) return 0U;

    threshold = (unsigned int)(0U - bound) % bound;
    do
    {
        x = feature_random_u32();
    } while (x < threshold);

    return x % bound;
}

void feature_generate_challenge(void)
{
    unsigned int op;

    /* Seed from live peripheral state; PRNG is for variation, not cryptography. */
    math_prng_state ^= (LPC_RTC->SEC + 1U) * 0x9E3779B9UL;
    math_prng_state ^= (LPC_RTC->MIN + 3U) * 0x85EBCA6BUL;
    math_prng_state ^= feature_timer_ticks + (unsigned int)stopwatch_seconds;
    if (math_prng_state == 0U) math_prng_state = 0xA341316CUL;

    /* Select operator first with equal probability; operands are then constrained. */
    op = feature_random_bounded(3U);
    math_operator = op;

    do
    {
        if (op == 0U)
        {
            math_a = feature_random_bounded(10U);
            math_b = feature_random_bounded(10U);
        }
        else if (op == 1U)
        {
            math_a = 1U + feature_random_bounded(9U);
            math_b = feature_random_bounded(math_a);
        }
        else
        {
            math_a = feature_random_bounded(10U);
            math_b = feature_random_bounded(10U);
        }
    } while ((op == 0U && math_a + math_b > 9U) ||
             (op == 2U && math_a * math_b > 9U));

    if (op == 0U) math_expected_answer = math_a + math_b;
    else if (op == 1U) math_expected_answer = math_a - math_b;
    else math_expected_answer = math_a * math_b;

    math_answer_digit = 0U;
    math_answer_entered = 0U;
    math_challenge_active = 1U;
}

void feature_display_challenge(void)
{
    char line[17];
    char op;

    op = (math_operator == 0U) ? '+' : ((math_operator == 1U) ? '-' : '*');
    lcd_clear();
    lcd_goto(0, 0);
    sprintf(line, "%u %c %u = ?", math_a, op, math_b);
    lcd_string(line);
    lcd_goto(1, 0);
    lcd_string("Digit A=OK D=CLR");
}

void feature_handle_challenge_key(unsigned char key)
{
    char line[17];

    if (!math_challenge_active)
        return;

    if (key >= '0' && key <= '9')
    {
        math_answer_digit = (unsigned int)(key - '0');
        math_answer_entered = 1U;
        lcd_goto(1, 0);
        sprintf(line, "Ans:%u A=OK D=CLR", math_answer_digit);
        lcd_string("                ");
        lcd_goto(1, 0);
        lcd_string(line);
    }
    else if (key == 'D')
    {
        math_answer_digit = 0U;
        math_answer_entered = 0U;
        feature_display_challenge();
    }
    else if (key == 'A')
    {
        if (!math_answer_entered)
        {
            lcd_goto(1, 0);
            lcd_string("Empty! Enter digit");
        }
        else if (math_answer_digit == math_expected_answer)
        {
            math_challenge_active = 0U;
            dismiss_notification();
            lcd_clear();
            lcd_goto(0, 0);
            lcd_string("Alarm dismissed");
        }
        else
        {
            lcd_goto(1, 0);
            lcd_string("Wrong! Try again ");
            delay_long();
            feature_display_challenge();
        }
    }
    /* Ignore E/F/B/C and other navigation keys while challenge is active. */
}

void feature_update_led_pattern(void) /* now calculates buzzer pulse duty */
{
    unsigned int level, duty;

    if (!notification_active || notification_type != NOTE_ALARM)
    {
        alarm_intensity_candidate = 0U;
        return;
    }

    feature_pattern_tick++;
    if (alarm_mode == 1U)
    {
        if (feature_pattern_tick >= 20U)
        {
            feature_pattern_tick = 0U;
            if (feature_breath_direction > 0)
            {
                if (feature_breath_level < 30U) feature_breath_level++;
                else feature_breath_direction = -1;
            }
            else
            {
                if (feature_breath_level > 0U) feature_breath_level--;
                else feature_breath_direction = 1;
            }
        }
        level = feature_breath_level; /* 0-30% pulse duty for gentle buzzer mode. */
    }
    else if (alarm_mode == 2U)
    {
        if (feature_pattern_tick >= 250U)
        {
            feature_pattern_tick = 0U;
            feature_breath_level = (feature_breath_level == 0U) ? 70U : 0U;
        }
        level = feature_breath_level; /* 70% pulse duty; slow beep cadence. */
    }
    else
    {
        if (feature_pattern_tick >= 100U)
        {
            feature_pattern_tick = 0U;
            feature_breath_level = (feature_breath_level == 0U) ? 100U : 0U;
        }
        level = feature_breath_level; /* Full saved maximum; rapid critical cadence. */
    }

    duty = (alarm_max_intensity * level) / 100U;
    if (duty > alarm_max_intensity) duty = alarm_max_intensity;
    if (duty > 100U) duty = 100U;
    alarm_intensity_candidate = duty;
}

void feature_alarm_configuration(unsigned int *intensity, unsigned int *mode)
{
    unsigned char key;
    unsigned int adc_value, candidate_intensity, candidate_mode;
    char line[17];

    candidate_intensity = *intensity;
    candidate_mode = *mode;

    lcd_clear();
    lcd_goto(0, 0);
    lcd_string("Set buzzer %");

    while (1)
    {
        adc_value = feature_adc_read_average();
        candidate_intensity = (adc_value * 100U) / ADC4_MAX_VALUE;
        lcd_goto(1, 0);
        sprintf(line, "%3u%% A=OK E=Back", candidate_intensity);
        lcd_string("                ");
        lcd_goto(1, 0);
        lcd_string(line);

        key = keypad_scan();
        if (key != 0U)
        {
            keypad_delay();
            if (keypad_scan() == key)
            {
                while (keypad_scan() != 0U) delay_short();
                if (key == 'A') break;
                if (key == 'E')
                {
                    *intensity = candidate_intensity; /* caller uses temp copies */
                    *mode = 0U; /* cancellation marker */
                    return;
                }
            }
        }
        service_events();
        if (notification_active)
        {
            *mode = 0U;
            return;
        }
    }

    lcd_clear();
    lcd_goto(0, 0);
    lcd_string("Mode: 1Gentle");
    lcd_goto(1, 0);
    lcd_string("2Normal 3Crit A");

    while (1)
    {
        key = keypad_scan();
        if (key != 0U)
        {
            keypad_delay();
            if (keypad_scan() == key)
            {
                while (keypad_scan() != 0U) delay_short();
                if (key == '1') { candidate_mode = 1U; break; }
                if (key == '2') { candidate_mode = 2U; break; }
                if (key == '3') { candidate_mode = 3U; break; }
                if (key == 'E')
                {
                    *mode = 0U;
                    return;
                }
            }
        }
        service_events();
        if (notification_active)
        {
            *mode = 0U;
            return;
        }
    }

    lcd_clear();
    lcd_goto(0, 0);
    lcd_string("A=Save E=Cancel");
    lcd_goto(1, 0);
    sprintf(line, "Buzz:%u%% M:%u", candidate_intensity, candidate_mode);
    lcd_string(line);

    while (1)
    {
        key = keypad_scan();
        if (key != 0U)
        {
            keypad_delay();
            if (keypad_scan() == key)
            {
                while (keypad_scan() != 0U) delay_short();
                if (key == 'A')
                {
                    *intensity = candidate_intensity;
                    *mode = candidate_mode;
                    return;
                }
                if (key == 'E')
                {
                    *mode = 0U;
                    return;
                }
            }
        }
        service_events();
        if (notification_active)
        {
            *mode = 0U;
            return;
        }
    }
}

static void feature_wait_for_rtc_change(unsigned int starting_second)
{
    volatile unsigned long timeout = 20000000UL;
    while (LPC_RTC->SEC == starting_second && timeout > 0UL)
        timeout--;
}

static void feature_show_diag_result(unsigned int state)
{
    if (state == DIAG_PASS) lcd_string("PASS");
    else if (state == DIAG_FAIL) lcd_string("FAIL");
    else if (state == DIAG_SKIPPED) lcd_string("SKIP");
    else lcd_string("NOT_RUN");
}

void feature_diagnostics(void)
{
    unsigned int rtc_before, rtc_after, adc_before, adc_after;
    unsigned int tick_before;
    unsigned char key;

    lcd_clear();
    lcd_goto(0, 0);
    lcd_string("Diagnostics");
    lcd_goto(1, 0);
    lcd_string("A=Run E=Return");

    while (1)
    {
        key = get_key();
        if (key == 'E' || key == 'N') return;
        if (key == 'A') break;
    }

    rtc_before = LPC_RTC->SEC;
    tick_before = feature_timer_ticks;
    adc_before = feature_adc_read_average();
    feature_wait_for_rtc_change(rtc_before);
    rtc_after = LPC_RTC->SEC;
    adc_after = feature_adc_read_average();

    diag_rtc = (rtc_before != rtc_after) ? DIAG_PASS : DIAG_FAIL;
    diag_adc = (adc_before <= ADC4_MAX_VALUE && adc_after <= ADC4_MAX_VALUE)
               ? DIAG_PASS : DIAG_FAIL;
    diag_pwm = feature_pwm_ready ? DIAG_PASS : DIAG_FAIL;
    diag_timer = (feature_timer_ticks != tick_before) ? DIAG_PASS : DIAG_FAIL;
    diag_keypad = DIAG_SKIPPED; /* Scanner software is present; physical key requires user observation. */

    lcd_clear();
    lcd_goto(0, 0);
    lcd_string("RTC:");
    feature_show_diag_result(diag_rtc);
    lcd_goto(0, 9);
    lcd_string("ADC:");
    feature_show_diag_result(diag_adc);
    lcd_goto(1, 0);
    lcd_string("BUZ:");
    feature_show_diag_result(diag_pwm);
    lcd_goto(1, 9);
    lcd_string("TMR:");
    feature_show_diag_result(diag_timer);

    while (1)
    {
        key = get_key();
        if (key == 'E' || key == 'N') return;
    }
}

/* ---------------- GPIO configuration ---------------- */
void gpio_init(void)
{
    /* LCD Pins Setup (P0.23-P0.28) */
    LPC_PINCON->PINSEL1 &= ~(0x0FFFUL << 14);
    LPC_GPIO0->FIODIR |= LCD_PIN_MASK;

    /* Keypad Setup */
    LPC_PINCON->PINSEL4 &= ~(0x0FFUL << 20);
    LPC_PINCON->PINSEL3 &= ~(0x0FFUL << 14);
    LPC_PINCON->PINMODE3 &= ~(0x0FFUL << 14);
    LPC_PINCON->PINMODE3 |=  (0x0FFUL << 14);

    LPC_GPIO2->FIODIR |= KEYPAD_ROW_MASK;
    LPC_GPIO2->FIOCLR = KEYPAD_ROW_MASK;
    LPC_GPIO1->FIODIR &= ~KEYPAD_COL_MASK;

    /* Buzzer on CNA5 pin 8 = P0.11. Configure ONLY this pin; leave other
       connector pins untouched to avoid conflicts with other modules. */
    LPC_PINCON->PINSEL0 &= ~(3UL << 22);       /* P0.11 function = GPIO */
    LPC_GPIO0->FIODIR |= BUZZER_PIN;
    LPC_GPIO0->FIOCLR  = BUZZER_PIN;           /* Buzzer OFF at startup */
}

/* ---------------- Display helpers ---------------- */
void display_home(void)
{
    unsigned int hour, minute, day, month, year;
    char line[17];

    hour   = LPC_RTC->HOUR;
    minute = LPC_RTC->MIN;
    day    = LPC_RTC->DOM;
    month  = LPC_RTC->MONTH;
    year   = LPC_RTC->YEAR;

    lcd_clear();

    sprintf(line, "%02u/%02u/%02u %02u:%02u",
            day, month, year % 100, hour, minute);
    lcd_goto(0, 0);
    lcd_string(line);

    lcd_goto(1, 0);
    lcd_string("Press A for Menu");
}

void update_home_time(void)
{
    unsigned int hour, minute, day, month, year;
    char line[17];

    hour   = LPC_RTC->HOUR;
    minute = LPC_RTC->MIN;
    day    = LPC_RTC->DOM;
    month  = LPC_RTC->MONTH;
    year   = LPC_RTC->YEAR;

    sprintf(line, "%02u/%02u/%02u %02u:%02u",
            day, month, year % 100, hour, minute);
    lcd_goto(0, 0);
    lcd_string(line);
}

void display_menu(void)
{
    lcd_clear();
    lcd_goto(0, 0);
    lcd_string("A:Diag B:Alarm");
    lcd_goto(1, 0);
    lcd_string("C:SW D:Timer E:Exit");
}

void show_notification(unsigned int type)
{
    char line[17];

    notification_active = 1;
    notification_type = type;
    
    /* Timer1 drives audible alarm patterns on the active-high P0.11 buzzer. */
    feature_pwm_phase = 0U;
    if (type != NOTE_ALARM)
        LPC_GPIO0->FIOSET = BUZZER_PIN;

    lcd_clear();

    if (type == NOTE_ALARM)
    {
        feature_pattern_tick = 0U;
        feature_breath_level = 0U;
        feature_breath_direction = 1;
        feature_generate_challenge();
        feature_update_led_pattern();
        feature_display_challenge();
    }
    else if (type == NOTE_COUNTDOWN)
    {
        lcd_goto(0, 0);
        lcd_string(" TIMER COMPLETE ");
        lcd_goto(1, 0);
        lcd_string("E=Dismiss");
    }
    else if (type == NOTE_STOPWATCH)
    {
        lcd_goto(0, 0);
        lcd_string("STOPWATCH STOP  ");
        lcd_goto(1, 0);
        sprintf(line, "%02u:%02u  E=Dismiss",
                (stopwatch_seconds / 60) % 100,
                stopwatch_seconds % 60);
        lcd_string(line);
    }
}

void service_events(void)
{
    if (notification_active)
    {
        if (notification_type == NOTE_ALARM)
            feature_update_led_pattern();
        return;
    }

    if (alarm_event)
    {
        alarm_event = 0;
        show_notification(NOTE_ALARM);
    }
    else if (timer_complete_event)
    {
        timer_complete_event = 0;
        show_notification(NOTE_COUNTDOWN);
    }
    else if (stopwatch_stop_event)
    {
        stopwatch_stop_event = 0;
        show_notification(NOTE_STOPWATCH);
    }
}

void dismiss_notification(void)
{
    LPC_GPIO0->FIOCLR = BUZZER_PIN; /* Silence buzzer immediately when dismissed */
    notification_active = 0;
    notification_type = NOTE_NONE;
    /* Removed return_home_requested = 1 and display_home() so menus can resume seamlessly */
}

void wait_notification(void)
{
    unsigned char key;

    while (notification_active)
    {
        if (notification_type == NOTE_ALARM)
            feature_update_led_pattern();

        key = keypad_scan();

        if (key != 0)
        {
            keypad_delay();
            if (keypad_scan() == key)
            {
                while (keypad_scan() != 0)
                    delay_short();

                if (notification_type == NOTE_ALARM && math_challenge_active)
                {
                    feature_handle_challenge_key(key);
                    if (!notification_active)
                        return;
                }
                else if (key == 'E')
                {
                    dismiss_notification();
                    return;
                }
            }
        }
    }
}

/* ---------------- RTC ---------------- */
static unsigned int get_compile_month(const char *d)
{
    if (d[0] == 'J' && d[1] == 'a' && d[2] == 'n') return 1;
    if (d[0] == 'F' && d[1] == 'e' && d[2] == 'b') return 2;
    if (d[0] == 'M' && d[1] == 'a' && d[2] == 'r') return 3;
    if (d[0] == 'A' && d[1] == 'p' && d[2] == 'r') return 4;
    if (d[0] == 'M' && d[1] == 'a' && d[2] == 'y') return 5;
    if (d[0] == 'J' && d[1] == 'u' && d[2] == 'n') return 6;
    if (d[0] == 'J' && d[1] == 'u' && d[2] == 'l') return 7;
    if (d[0] == 'A' && d[1] == 'u' && d[2] == 'g') return 8;
    if (d[0] == 'S' && d[1] == 'e' && d[2] == 'p') return 9;
    if (d[0] == 'O' && d[1] == 'c' && d[2] == 't') return 10;
    if (d[0] == 'N' && d[1] == 'o' && d[2] == 'v') return 11;
    if (d[0] == 'D' && d[1] == 'e' && d[2] == 'c') return 12;
    return 1;
}

void rtc_init(void)
{
    const char *t = __TIME__; 
    const char *d = __DATE__; 

    LPC_SC->PCONP |= (1UL << 9);

    LPC_RTC->CCR = 0x02;  

    LPC_RTC->HOUR  = (unsigned int)((t[0] - '0') * 10 + (t[1] - '0'));
    LPC_RTC->MIN   = (unsigned int)((t[3] - '0') * 10 + (t[4] - '0'));
    LPC_RTC->SEC   = (unsigned int)((t[6] - '0') * 10 + (t[7] - '0'));

    LPC_RTC->DOM   = (unsigned int)(((d[4] == ' ') ? 0 : (d[4] - '0') * 10) + (d[5] - '0'));
    LPC_RTC->MONTH = get_compile_month(d);
    LPC_RTC->YEAR  = (unsigned int)((d[7] - '0') * 1000 + (d[8] - '0') * 100 +
                                    (d[9] - '0') * 10   + (d[10] - '0'));

    LPC_RTC->CCR = 0x01;  

    LPC_RTC->ILR = 0x03;
    NVIC_ClearPendingIRQ(RTC_IRQn);
    NVIC_EnableIRQ(RTC_IRQn);
}

void rtc_set_alarm(unsigned int hour, unsigned int minute)
{
    LPC_RTC->AMR = 0xFF;   

    LPC_RTC->ALSEC  = 0;
    LPC_RTC->ALMIN  = minute;
    LPC_RTC->ALHOUR = hour;

    LPC_RTC->AMR = 0xF8;

    LPC_RTC->ILR = 0x03;
    NVIC_ClearPendingIRQ(RTC_IRQn);

    alarm_hour = hour;
    alarm_minute = minute;
    alarm_enabled = 1;
    alarm_event = 0;
}

void RTC_IRQHandler(void)
{
    if (LPC_RTC->ILR & 0x02UL)
    {
        LPC_RTC->ILR = 0x02;

        if (alarm_enabled)
        {
            alarm_enabled = 0;
            LPC_RTC->AMR = 0xFF;   
            alarm_event = 1;
        }
    }

    if (LPC_RTC->ILR & 0x01UL)
        LPC_RTC->ILR = 0x01;
}

/* ---------------- Timer0: one-second tick ---------------- */
void timer0_init(void)
{
    LPC_SC->PCONP |= (1UL << 1);

    LPC_SC->PCLKSEL0 &= ~(3UL << 2);
    LPC_SC->PCLKSEL0 |=  (1UL << 2);

    LPC_TIM0->TCR = 0x02;
    LPC_TIM0->CTCR = 0x00;

    LPC_TIM0->PR = (SystemCoreClock / 1000000UL) - 1UL;
    LPC_TIM0->MR0 = 999999UL;
    LPC_TIM0->MCR = 0x03;      
    LPC_TIM0->IR = 0xFF;

    NVIC_ClearPendingIRQ(TIMER0_IRQn);
    NVIC_EnableIRQ(TIMER0_IRQn);

    LPC_TIM0->TCR = 0x01;
}

void TIMER0_IRQHandler(void)
{
    if (LPC_TIM0->IR & 0x01UL)
    {
        LPC_TIM0->IR = 0x01;

        /* Buzzer cadence runs on Timer1; keep Timer0 for original 1-second timing. */

        if (stopwatch_running)
            stopwatch_seconds++;

        if (countdown_running && remaining_seconds > 0)
        {
            remaining_seconds--;

            if (remaining_seconds == 0)
            {
                countdown_running = 0;
                timer_complete_event = 1;
            }
        }
    }
}

/* ---------------- Menus ---------------- */
void alarm_menu(void)
{
    char digits[5];
    unsigned int hour, minute;
    char line[17];

    lcd_clear();
    lcd_goto(0, 0);
    lcd_string("Enter Alarm HHMM");
    lcd_goto(1, 0);

    if (!read_four_digits(digits))
    {
        return_home_requested = 1;
        display_home();
        return;
    }

    hour = (unsigned int)((digits[0] - '0') * 10 + (digits[1] - '0'));
    minute = (unsigned int)((digits[2] - '0') * 10 + (digits[3] - '0'));

    if (hour > 23 || minute > 59)
    {
        lcd_clear();
        lcd_goto(0, 0);
        lcd_string("Invalid HHMM");
        lcd_goto(1, 0);
        lcd_string("Press any key");
        get_key();
        return_home_requested = 1;
        display_home();
        return;
    }

    {
        unsigned int staged_intensity = alarm_max_intensity;
        unsigned int staged_mode = alarm_mode;

        feature_alarm_configuration(&staged_intensity, &staged_mode);
        if (staged_mode == 0U)
        {
            /* Cancelled: keep the previously saved alarm configuration.
               If an alarm interrupted setup, do not overwrite its challenge screen. */
            if (!notification_active)
                display_home();
            return;
        }

        alarm_max_intensity = staged_intensity;
        alarm_mode = staged_mode;
    }

    rtc_set_alarm(hour, minute);

    lcd_clear();
    lcd_goto(0, 0);
    lcd_string("Alarm Set:");
    lcd_goto(1, 0);
    sprintf(line, "%02u:%02u  *=Exit", hour, minute);
    lcd_string(line);

    while (1)
    {
        service_events();

        if (notification_active)
        {
            wait_notification();
            /* Redraw the interface after dismissing notification */
            lcd_clear();
            lcd_goto(0, 0);
            lcd_string("Alarm Set:");
            lcd_goto(1, 0);
            sprintf(line, "%02u:%02u  *=Exit", hour, minute);
            lcd_string(line);
            continue;
        }

        keypad_key = get_key();

        if (keypad_key == 'N')
        {
            /* Triggered if notification was dismissed inside get_key() */
            lcd_clear();
            lcd_goto(0, 0);
            lcd_string("Alarm Set:");
            lcd_goto(1, 0);
            sprintf(line, "%02u:%02u  *=Exit", hour, minute);
            lcd_string(line);
            continue;
        }
        else if (keypad_key == 'E' || return_home_requested)
        {
            /* Exits the menu when E is pressed legitimately */
            return_home_requested = 1;
            display_home();
            return;
        }
    }
}

void stopwatch_menu(void)
{
    char line[17];
    unsigned int last_displayed_seconds = 0xFFFFFFFFUL;

    stopwatch_seconds = 0;
    stopwatch_running = 1;

    while (1)
    {
        service_events();

        if (notification_active)
        {
            wait_notification();
            /* Force stopwatch redraw after dismissing notification */
            last_displayed_seconds = 0xFFFFFFFFUL; 
            continue; 
        }

        if (last_displayed_seconds != stopwatch_seconds)
        {
            last_displayed_seconds = stopwatch_seconds;

            lcd_goto(0, 0);
            lcd_string("STOPWATCH       ");

            sprintf(line, "%02u:%02u #=Stop",
                    (stopwatch_seconds / 60) % 100,
                    stopwatch_seconds % 60);
            lcd_goto(1, 0);
            lcd_string("                ");
            lcd_goto(1, 0);
            lcd_string(line);
        }

        keypad_key = keypad_scan();
        if (keypad_key != 0)
        {
            keypad_delay();
            if (keypad_scan() == keypad_key)
            {
                while (keypad_scan() != 0)
                    delay_short();

                if (keypad_key == 'F')
                {
                    stopwatch_running = 0;
                    stopwatch_stop_event = 1;
                    service_events();

                    if (notification_active)
                    {
                        wait_notification();
                        last_displayed_seconds = 0xFFFFFFFFUL; 
                        continue; 
                    }
                }
                else if (keypad_key == 'E')
                {
                    /* Exits the menu when E is pressed legitimately */
                    stopwatch_running = 0;
                    return_home_requested = 1;
                    display_home();
                    return;
                }
            }
        }
    }
}

void countdown_menu(void)
{
    char digits[5];
    char line[17];
    unsigned int minutes, seconds;
    unsigned int last_displayed_seconds = 0xFFFFFFFFUL;

    lcd_clear();
    lcd_goto(0, 0);
    lcd_string("Enter Timer MMSS");
    lcd_goto(1, 0);

    if (!read_four_digits(digits))
    {
        return_home_requested = 1;
        display_home();
        return;
    }

    minutes = (unsigned int)((digits[0] - '0') * 10 + (digits[1] - '0'));
    seconds = (unsigned int)((digits[2] - '0') * 10 + (digits[3] - '0'));

    if (seconds > 59 || (minutes == 0 && seconds == 0))
    {
        lcd_clear();
        lcd_goto(0, 0);
        lcd_string("Invalid MMSS");
        lcd_goto(1, 0);
        lcd_string("Press any key");
        get_key();
        return_home_requested = 1;
        display_home();
        return;
    }

    remaining_seconds = minutes * 60 + seconds;
    countdown_running = 1;

    while (1)
    {
        service_events();

        if (notification_active)
        {
            wait_notification();
            /* Force timer redraw after dismissing notification */
            last_displayed_seconds = 0xFFFFFFFFUL; 
            continue; 
        }

        if (last_displayed_seconds != remaining_seconds)
        {
            last_displayed_seconds = remaining_seconds;

            lcd_goto(0, 0);
            lcd_string("COUNTDOWN       ");

            sprintf(line, "%02u:%02u *=Exit",
                    remaining_seconds / 60,
                    remaining_seconds % 60);
            lcd_goto(1, 0);
            lcd_string("                ");
            lcd_goto(1, 0);
            lcd_string(line);
        }

        keypad_key = keypad_scan();
        if (keypad_key != 0)
        {
            keypad_delay();
            if (keypad_scan() == keypad_key)
            {
                while (keypad_scan() != 0)
                    delay_short();

                if (keypad_key == 'E')
                {
                    /* Exits the menu when E is pressed legitimately */
                    return_home_requested = 1;
                    display_home();
                    return;
                }
            }
        }
    }
}

/* ---------------- Main ---------------- */
int main(void)
{
    unsigned int last_displayed_second = 60;

    SystemInit();
    SystemCoreClockUpdate();

    gpio_init();
    lcd_init();
    rtc_init();
    timer0_init();
    feature_adc_init();
    feature_timer1_init();

    /* Brief startup software self-check; physical LCD/buzzer/keypad tests remain interactive. */
    diag_rtc = DIAG_NOT_RUN;
    diag_adc = DIAG_NOT_RUN;
    diag_pwm = feature_pwm_ready ? DIAG_PASS : DIAG_FAIL;
    diag_timer = DIAG_NOT_RUN;
    diag_keypad = DIAG_NOT_RUN;

    lcd_clear();
    lcd_goto(0, 0);
    lcd_string("System Self-Test");
    lcd_goto(1, 0);
    lcd_string("RTC/ADC/TMR/BUZ");

    {
        unsigned int rtc_sec_before = LPC_RTC->SEC;
        unsigned int timer_before = feature_timer_ticks;
        unsigned int adc_value = feature_adc_read_average();
        feature_wait_for_rtc_change(rtc_sec_before);
        diag_rtc = (LPC_RTC->SEC != rtc_sec_before) ? DIAG_PASS : DIAG_FAIL;
        diag_adc = (adc_value <= ADC4_MAX_VALUE) ? DIAG_PASS : DIAG_FAIL;
        diag_timer = (feature_timer_ticks != timer_before) ? DIAG_PASS : DIAG_FAIL;
        diag_pwm = feature_pwm_ready ? DIAG_PASS : DIAG_FAIL;
        diag_keypad = DIAG_SKIPPED;
    }

    display_home();

    while (1)
    {
        service_events();

        if (notification_active)
        {
            wait_notification();
            last_displayed_second = 60; /* Force home time redraw */
            continue;
        }

        if (LPC_RTC->SEC != last_displayed_second)
        {
            last_displayed_second = LPC_RTC->SEC;
            update_home_time();
        }

        keypad_key = keypad_scan();
        if (keypad_key != 0)
        {
            keypad_delay();
            if (keypad_scan() == keypad_key)
            {
                while (keypad_scan() != 0)
                {
                    service_events();
                    delay_short();
                    if (notification_active)
                        break;
                }

                if (notification_active)
                    continue;

                if (keypad_key == 'A')
                {
                    return_home_requested = 0;
                    display_menu();

                    while (1)
                    {
                        service_events();

                        if (notification_active)
                        {
                            wait_notification();
                            display_menu(); /* Redraw menu */
                            continue;
                        }

                        if (return_home_requested)
                        {
                            return_home_requested = 0;
                            display_home();
                            last_displayed_second = 60;
                            break;
                        }

                        keypad_key = get_key();

                        if (keypad_key == 'N')
                        {
                            display_menu(); /* Redraw menu if notification fired while inside get_key() */
                            continue;
                        }
                        else if (keypad_key == 'A')
                            feature_diagnostics();
                        else if (keypad_key == 'B')
                            alarm_menu();
                        else if (keypad_key == 'C')
                            stopwatch_menu();
                        else if (keypad_key == 'D')
                            countdown_menu();
                        else if (keypad_key == 'E')
                        {
                            /* Exits the menu when E is pressed legitimately */
                            return_home_requested = 1;
                            display_home();
                        }

                        if (return_home_requested)
                        {
                            return_home_requested = 0;
                            display_home();
                            last_displayed_second = 60;
                            break;
                        }

                        display_menu();
                    }
                }
            }
        }
    }
}