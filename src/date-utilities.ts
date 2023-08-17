import { NumberUtilities } from "./number-utilities";
import { ObjectUtilities } from "./object-utilities";
import { StringUtilities } from "./string-utilities";

const DAY_NAMES = [
  'Sunday',
  'Monday',
  'Tuesday',
  'Wednesday',
  'Thursday',
  'Friday',
  'Saturday',
];

const MONTH_NAMES = [
  'January',
  'February',
  'March',
  'April',
  'May',
  'June',
  'July',
  'August',
  'September',
  'October',
  'November',
  'December',
];

type DateProperties = {
  hoursIn12hFormat: string,
  hoursIn24hFormat: string,
  minutes: string,
  seconds: string,
  amPm: "AM" | "PM",
  timezone: string,
  day: string,
  dayOfTheWeek: string,
  dayName: string,
  month: string,
  monthName: string,
  shortMonthName: string,
  year: string,
};

type DateFormatCallback = (properties: DateProperties) => string;

export class DateUtilities {

  public static getDayName(day: number): string {
    if (day < 0 || day >= DAY_NAMES.length) { return StringUtilities.getEmptyString(); }

    return DAY_NAMES[day];
  }

  public static getMonthName(month: number): string {
    if (month < 0 || month >= MONTH_NAMES.length) { return StringUtilities.getEmptyString(); }

    return MONTH_NAMES[month];
  }

  public static getShortMonthName(month: number): string {
    const monthName = this.getMonthName(month);

    return monthName.substring(0, 3);
  }

  public static extractDateProperties(date: Date): undefined | DateProperties {
    // if date is not an instance of the Date class,
    // we shall return an empty string...
    if (!(date instanceof Date)) { return undefined; }

    let hours = date.getHours();
    const hoursIn24hFormat = NumberUtilities.ensureDoubleDigit(hours);
    const minutes = NumberUtilities.ensureDoubleDigit(date.getMinutes());
    const seconds = NumberUtilities.ensureDoubleDigit(date.getSeconds());
    const amPm = hours < 12 ? "AM" : "PM";
    const timezone = -date.getTimezoneOffset() / 60;
    let timezoneAsString = NumberUtilities.ensureDoubleDigit(timezone);

    if (timezone > 0) { timezoneAsString = `+${timezoneAsString}`; }

    hours = hours % 12;
    // if hours is equal to zero (0), we make it twelve...
    hours = hours ? hours : 12;

    const hoursIn12hFormat = NumberUtilities.ensureDoubleDigit(hours);
    const day = NumberUtilities.ensureDoubleDigit(date.getDate());
    const dayOfTheWeek = NumberUtilities.ensureDoubleDigit(date.getDay() + 1);
    const dayName = this.getDayName(date.getDay());
    const month = NumberUtilities.ensureDoubleDigit(date.getMonth() + 1);
    const monthName = this.getMonthName(date.getMonth());
    const shortMonthName = this.getShortMonthName(date.getMonth());
    const year = date.getFullYear();

    return {
      hoursIn12hFormat,
      hoursIn24hFormat,
      minutes,
      seconds,
      amPm,
      timezone: timezoneAsString,
      day,
      dayOfTheWeek,
      dayName,
      month,
      monthName,
      shortMonthName,
      year: `${year}`,
    };
  }

  public static formatDate(date: Date, callback: DateFormatCallback): string {
    const dateProperties = this.extractDateProperties(date);

    if (!ObjectUtilities.isObject(dateProperties)) { return StringUtilities.getEmptyString(); }

    // actual formatting is done by the callback function...
    let formattedDate = callback(dateProperties!);
    formattedDate = StringUtilities.getDefaultIfUndefinedOrNullOrEmpty(
      formattedDate, StringUtilities.getEmptyString(), true);

    return formattedDate;
  }
}
