import { NumberUtilities } from "./number-utilities";

const DEFAULT_THREAD_SLEEP_TIMEOUT_IN_MILLISECONDS = 10;
const DEFAULT_WAITING_THREAD_SLEEP_TIMEOUT_IN_MILLISECONDS = 1 * 1000;

type WaitCancellationCallback = () => boolean | Promise<boolean>;

export class ThreadUtilities {

  /**
   * Suspends the current thread for the specified number of milliseconds.
   * @param timeoutInMilliseconds The number of milliseconds for which the
   * thread is suspended. Default value is 10 milliseconds.
   * @returns A promise that resolves to void.
   */
  public static async sleepAsync(timeoutInMilliseconds?: number): Promise<void> {
    return new Promise<void>(resolve => {
      if (!NumberUtilities.isPositiveNumber(timeoutInMilliseconds)) {
        timeoutInMilliseconds = DEFAULT_THREAD_SLEEP_TIMEOUT_IN_MILLISECONDS;
      }

      const timeout = setTimeout(() => {
        // clears the timeout object...
        clearTimeout(timeout);
        // resolves the promise...
        resolve();
      }, timeoutInMilliseconds);
    });
  }

  private static async executeWaitCancellationCallbackAsync(
    callback?: WaitCancellationCallback): Promise<boolean> {
    if (typeof callback !== "function") { return false; }

    const shallCancel = await callback();

    return shallCancel === true;
  }

  /**
   * Keeps a thread in waiting state until the wait cancellation callback returns true.
   * If no callback function is provided, the thread shall stay in the waiting state indefinitely.
   * @param callback The cancellation callback function to break out of the waiting state. If this
   * function returns true, the thread will break out of the waiting state. If not provided,
   * the thread shall stay in the waiting state indefinitely.
   * @param sleepTimeoutInMilliseconds The number of milliseconds for which the thread is suspended.
   * Default value is 1 second.
   */
  public static async waitAsync(callback?: WaitCancellationCallback,
    sleepTimeoutInMilliseconds?: number): Promise<void> {
    return new Promise<void>(async resolve => {
      let shallCancel = await this.executeWaitCancellationCallbackAsync(callback);

      // checks if the thread shall break out of the waiting state immediately...
      if (shallCancel) { return resolve(); }
      // if the provided sleep timeout is not a positive number...
      if (!NumberUtilities.isPositiveNumber(sleepTimeoutInMilliseconds)) {
        // we shall set the default value...
        sleepTimeoutInMilliseconds = DEFAULT_WAITING_THREAD_SLEEP_TIMEOUT_IN_MILLISECONDS;
      }

      const interval = setInterval(async () => {
        // checks if the thread shall break out of the waiting state...
        shallCancel = await this.executeWaitCancellationCallbackAsync(callback);

        // if the thread shall not break out of the waiting state, we shall return...
        if (!shallCancel) { return; }

        // otherwise we shall clear the interval to stop waiting...
        clearInterval(interval);
        // resolves the promise...
        resolve();
      }, sleepTimeoutInMilliseconds);
    });
  }
}
