use std::cmp::Eq;
use std::println;

global UNIX_EPOCH_YEAR: u32 = 1970;
global SECONDS_IN_DAY: u32 = 86400;

pub struct Date {
    pub day: u8,
    pub month: u8,
    pub year: u32,
}

fn get_number_from_utf8_code(code: u8) -> u8 {
    assert(code >= 48 & code <= 57);
    code - 48
}

fn number_to_utf8_code(number: u8) -> u8 {
    assert(number >= 0 & number <= 9);
    number + 48
}

impl Date {
    pub fn new(year: u32, month: u8, day: u8) -> Self {
        assert(month >= 1 & month <= 12);
        assert(day >= 1 & day <= 31);
        let date = Self { day: day, month: month, year: year };
        assert(day <= date.get_days_in_month(month));
        date
    }

    pub fn from_bytes_short_year(date: [u8; 6], threshold_date: Date) -> Self {
        let firstYearDigit = get_number_from_utf8_code(date[0]);
        let secondYearDigit = get_number_from_utf8_code(date[1]);

        let mut year: u32 = firstYearDigit as u32 * 10 + secondYearDigit as u32;

        let firstMonthDigit = get_number_from_utf8_code(date[2]);
        let secondMonthDigit = get_number_from_utf8_code(date[3]);

        let month = firstMonthDigit * 10 + secondMonthDigit;

        let firstDayDigit = get_number_from_utf8_code(date[4]);
        let secondDayDigit = get_number_from_utf8_code(date[5]);

        let day = firstDayDigit * 10 + secondDayDigit;

        let mut currentYear: u32 = threshold_date.year % 100;

        // This way we have a smooth 100 years period according to a threshold year
        // Taking the current year as threshold year (for birthdates for example)
        // if the current year is 2023, then 24 will be interpreted as 1924
        // while 22 will be interpreted as 2022
        // A bit problematic for people over 100 years old
        if year <= currentYear {
            year += 2000;
        } else {
            year += 1900;
        }

        Self { day: day, month: month, year: year }
    }

    pub fn from_bytes_long_year(date: [u8; 8]) -> Self {
        let firstYearDigit = get_number_from_utf8_code(date[0]);
        let secondYearDigit = get_number_from_utf8_code(date[1]);
        let thirdYearDigit = get_number_from_utf8_code(date[2]);
        let fourthYearDigit = get_number_from_utf8_code(date[3]);

        let year: u32 = firstYearDigit as u32 * 1000
            + secondYearDigit as u32 * 100
            + thirdYearDigit as u32 * 10
            + fourthYearDigit as u32;

        let firstMonthDigit = get_number_from_utf8_code(date[4]);
        let secondMonthDigit = get_number_from_utf8_code(date[5]);

        let month = firstMonthDigit * 10 + secondMonthDigit;

        let firstDayDigit = get_number_from_utf8_code(date[6]);
        let secondDayDigit = get_number_from_utf8_code(date[7]);

        let day = firstDayDigit * 10 + secondDayDigit;

        Self { day: day, month: month, year: year }
    }

    pub fn from_str_short_year(date: str<6>, threshold_date: Date) -> Self {
        let date_bytes = date.as_bytes();
        Date::from_bytes_short_year(date_bytes, threshold_date)
    }

    pub fn from_str_long_year(date: str<8>) -> Self {
        let date_bytes = date.as_bytes();
        Date::from_bytes_long_year(date_bytes)
    }

    fn count_leap_years_since_epoch(year: u32, epoch_year: u32) -> u32 {
        let y = year - 1;
        let leaps_up_to_y = y / 4 - y / 100 + y / 400;
        let leaps_up_to_epoch_year =
            (epoch_year - 1) / 4 - (epoch_year - 1) / 100 + (epoch_year - 1) / 400;
        leaps_up_to_y - leaps_up_to_epoch_year
    }

    fn days_since_epoch(year: u32, epoch_year: u32) -> u32 {
        365 * (year - epoch_year) + Date::count_leap_years_since_epoch(year, epoch_year)
    }

    fn estimate_start_day_and_year(days: u32, epoch_year: u32) -> (u32, u32) {
        let first_guess_year = epoch_year + days / 365;

        let days_lower_bound = if first_guess_year > epoch_year {
            Date::days_since_epoch(first_guess_year - 1, epoch_year)
        } else {
            0
        };
        let day_guess = Date::days_since_epoch(first_guess_year, epoch_year);
        let days_upper_bound = Date::days_since_epoch(first_guess_year + 1, epoch_year);

        let use_lower_bound = (days >= days_lower_bound) & (days < day_guess);
        let use_upper_bound = days >= days_upper_bound;

        let mut best_year = first_guess_year;
        let mut best_start_day = day_guess;

        best_year = if use_lower_bound {
            first_guess_year - 1
        } else {
            best_year
        };
        best_start_day = if use_lower_bound {
            days_lower_bound
        } else {
            best_start_day
        };

        best_year = if use_upper_bound {
            first_guess_year + 1
        } else {
            best_year
        };
        best_start_day = if use_upper_bound {
            days_upper_bound
        } else {
            best_start_day
        };

        (best_year, best_start_day)
    }

    pub fn from_timestamp_with_epoch(timestamp: u64, epoch_year: u32) -> Self {
        let days = timestamp / SECONDS_IN_DAY as u64;
        let (year, year_start_day) = Date::estimate_start_day_and_year(days as u32, epoch_year);
        let day_of_year = days as u32 - year_start_day;

        let is_leap = Date::is_leap_year(Date::new(year, 1, 1));

        let days_at_month_start: [u32; 13] = if is_leap {
            [0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366]
        } else {
            [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365]
        };

        let mut month: u32 = 1;
        for i in 0..12 {
            let advance = day_of_year >= days_at_month_start[i + 1];
            month = if advance { month + 1 } else { month };
        }

        let day: u32 = day_of_year - days_at_month_start[(month - 1) as u32] + 1;
        Date::new(year, month as u8, day as u8)
    }

    pub fn from_timestamp(timestamp: u64) -> Self {
        Date::from_timestamp_with_epoch(timestamp, UNIX_EPOCH_YEAR)
    }

    pub fn get_duration_in_days(self: Self, other: Self, absolute: bool) -> i64 {
        let mut duration_years = self.get_duration_between_years(other);
        let mut duration_months = self.get_duration_between_months(other);
        let mut duration_days = self.day as i64 - other.day as i64;
        if (self.year < other.year) {
            if (other.is_leap_year() & other.month > 2 & self.month > 2) {
                duration_days -= 1;
            }
        } else if (self.year > other.year) {
            if (self.is_leap_year() & self.month > 2 & other.month > 2) {
                duration_days += 1;
            }
        }
        let totalDuration: i64 = duration_years + duration_months + duration_days;

        if (totalDuration < 0) & absolute {
            -1 * totalDuration
        } else {
            totalDuration
        }
    }

    pub fn gt(self: Self, other: Self) -> bool {
        self.get_duration_in_days(other, false) > 0
    }

    pub fn lt(self: Self, other: Self) -> bool {
        self.get_duration_in_days(other, false) < 0
    }

    pub fn eq(self: Self, other: Self) -> bool {
        (self.day == other.day) & (self.month == other.month) & (self.year == other.year)
    }

    pub fn ne(self: Self, other: Self) -> bool {
        !self.eq(other)
    }

    pub fn gte(self: Self, other: Self) -> bool {
        self.get_duration_in_days(other, false) >= 0
    }

    pub fn lte(self: Self, other: Self) -> bool {
        self.get_duration_in_days(other, false) <= 0
    }

    pub fn println(self: Self) {
        let year = self.year;
        let month = self.month;
        let day = self.day;
        // Let's write the date in the YYYY-MM-DD format
        // since people don't agree on which format is best
        // between MM/DD/YYYY and DD/MM/YYYY
        if (month < 10) & (day < 10) {
            println(f"Date: {year}-0{month}-0{day}");
        } else if month < 10 {
            println(f"Date: {year}-0{month}-{day}");
        } else if day < 10 {
            println(f"Date: {year}-{month}-0{day}");
        } else {
            println(f"Date: {year}-{month}-{day}");
        }
    }

    pub fn to_bytes(self: Self) -> [u8; 8] {
        let mut date: [u8; 8] = [0; 8];

        let firstYearDigit = self.year / 1000;
        let secondYearDigit = (self.year - firstYearDigit * 1000) / 100;
        let thirdYearDigit = (self.year - firstYearDigit * 1000 - secondYearDigit * 100) / 10;
        let fourthYearDigit =
            self.year - firstYearDigit * 1000 - secondYearDigit * 100 - thirdYearDigit * 10;

        date[0] = number_to_utf8_code(firstYearDigit as u8);
        date[1] = number_to_utf8_code(secondYearDigit as u8);
        date[2] = number_to_utf8_code(thirdYearDigit as u8);
        date[3] = number_to_utf8_code(fourthYearDigit as u8);

        let firstMonthDigit = self.month / 10;
        let secondMonthDigit = self.month - firstMonthDigit * 10;

        date[4] = number_to_utf8_code(firstMonthDigit as u8);
        date[5] = number_to_utf8_code(secondMonthDigit as u8);

        let firstDayDigit = self.day / 10;
        let secondDayDigit = self.day - firstDayDigit * 10;

        date[6] = number_to_utf8_code(firstDayDigit as u8);
        date[7] = number_to_utf8_code(secondDayDigit as u8);

        date
    }

    pub fn to_string(self: Self) -> str<8> {
        let date_bytes = self.to_bytes();
        date_bytes.as_str_unchecked()
    }

    pub fn to_timestamp_with_epoch(self: Self, epoch_year: u32) -> u32 {
        let days = self.get_duration_in_days(Date::new(epoch_year, 1, 1), true);
        days as u32 * SECONDS_IN_DAY
    }

    pub fn to_timestamp(self: Self) -> u32 {
        self.to_timestamp_with_epoch(UNIX_EPOCH_YEAR)
    }

    pub fn is_leap_year(self: Self) -> bool {
        ((self.year % 4 == 0) & (self.year % 100 != 0)) | (self.year % 400 == 0)
    }

    pub fn leap_year_count(year: u32) -> i32 {
        (year / 4) as i32 - (year / 100) as i32 + (year / 400) as i32
    }

    pub fn get_days_in_month(self: Self, month: u8) -> u8 {
        assert(month >= 1 & month <= 12);
        if month == 2 {
            if self.is_leap_year() {
                29
            } else {
                28
            }
        } else {
            if (month == 1)
                | (month == 3)
                | (month == 5)
                | (month == 7)
                | (month == 8)
                | (month == 10)
                | (month == 12) {
                31
            } else {
                30
            }
        }
    }

    pub fn get_duration_between_months(self: Self, other: Self) -> i64 {
        assert(self.month >= 1 & self.month <= 12);
        assert(other.month >= 1 & other.month <= 12);
        let mut duration: i64 = 0;
        if (self.month < other.month) {
            for month in 1..13 {
                if month >= self.month & month < other.month {
                    duration -= other.get_days_in_month(month) as i64;
                }
            }
        } else {
            for month in 1..13 {
                if month >= other.month & month < self.month {
                    duration += self.get_days_in_month(month) as i64;
                }
            }
        }
        duration
    }

    pub fn get_duration_between_years(self: Self, other: Self) -> i64 {
        let mut duration: i64 = 0;
        if (self.year < other.year) {
            let mut leap_year_count: i32 =
                Date::leap_year_count(other.year - 1) - Date::leap_year_count(self.year);
            if self.is_leap_year() {
                leap_year_count += 1;
            }
            duration -= leap_year_count as i64 * 366;
            duration -=
                (other.year as i64 - self.year as i64 - leap_year_count as i64) as i64 * 365;
        } else if (self.year > other.year) {
            let mut leap_year_count: i32 =
                Date::leap_year_count(self.year - 1) - Date::leap_year_count(other.year);
            if other.is_leap_year() {
                leap_year_count += 1;
            }
            duration += leap_year_count as i64 * 366;
            duration +=
                (self.year as i64 - other.year as i64 - leap_year_count as i64) as i64 * 365;
        }
        duration
    }

    pub fn add_years(self: Self, years: u32) -> Self {
        Self { day: self.day, month: self.month, year: self.year + years }
    }

    pub fn sub_years(self: Self, years: u32) -> Self {
        Self { day: self.day, month: self.month, year: self.year - years }
    }

    pub fn add_months(self: Self, months: u32) -> Self {
        let mut newMonth = self.month as u32 + months;
        let mut newYear = self.year;
        let yearToAdd = (newMonth - 1) / 12;
        if newMonth > 12 {
            newYear += yearToAdd as u32;
            newMonth -= 12 * yearToAdd;
        }
        Self { day: self.day, month: newMonth as u8, year: newYear }
    }

    pub fn sub_months(self: Self, months: u32) -> Self {
        let mut newMonth = self.month as i32 - months as i32;
        let mut newYear = self.year;
        if newMonth < 1 {
            let yearToSub = ((newMonth as i32 - 12 as i32) * -1) / 12;
            newYear -= yearToSub as u32;
            newMonth += 12 * yearToSub;
        }
        Self { day: self.day, month: newMonth as u8, year: newYear }
    }

    pub fn add_days(self: Self, days: u32) -> Self {
        let mut newDay = self.day as u32 + days;
        let mut newMonth = self.month as u32;
        let mut newYear = self.year;
        let mut date = Self { day: newDay as u8, month: newMonth as u8, year: newYear };
        if newDay > self.get_days_in_month(self.month) as u32 {
            let max_months = (newDay / 30) + 1;
            let bound = self.month as u64 + max_months as u64;
            for _ in self.month as u64..bound as u64 {
                let days_in_month = date.get_days_in_month(newMonth as u8) as u32;
                if newDay > days_in_month {
                    newDay -= days_in_month;
                    newMonth += 1;
                    if newMonth > 12 {
                        newYear += 1;
                        newMonth = 1;
                    }
                    // We need to mutate the date object inside the loop
                    // so we can use get_days_in_month properly
                    date.day = newDay as u8;
                    date.year = newYear;
                    date.month = newMonth as u8;
                }
            }
        }
        date
    }

    // Performance could be improved
    pub fn sub_days(self: Self, days: u32) -> Self {
        let mut newDay = self.day as i32 - days as i32;
        let mut newMonth = self.month as i32;
        let mut newYear = self.year;
        let mut date = Self { day: newDay as u8, month: newMonth as u8, year: newYear };
        if newDay < 1 {
            let max_months = (self.day as u32 + days) / 30 + 1;
            let bound = self.month as u64 + max_months as u64;
            for _ in self.month as u64..bound as u64 {
                let days_in_month = date.get_days_in_month(newMonth as u8) as i32;
                if newDay < 1 {
                    newDay += days_in_month;
                    newMonth -= 1;
                    if newMonth < 1 {
                        newYear -= 1;
                        newMonth = 12;
                    }
                    // We need to mutate the date object inside the loop
                    // so we can use get_days_in_month properly
                    date.day = newDay as u8;
                    date.year = newYear;
                    date.month = newMonth as u8;
                }
            }
        }
        date
    }
}

impl Eq for Date {
    fn eq(self: Self, other: Self) -> bool {
        self.eq(other)
    }
}
