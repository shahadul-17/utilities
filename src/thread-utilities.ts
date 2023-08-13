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
    let shallCancel = await this.executeWaitCancellationCallbackAsync(callback);

    if (!NumberUtilities.isPositiveNumber(sleepTimeoutInMilliseconds)) {
      sleepTimeoutInMilliseconds = DEFAULT_WAITING_THREAD_SLEEP_TIMEOUT_IN_MILLISECONDS;
    }

    while (!shallCancel) {
      // suspends the waiting thread for a certain time...
      await this.sleepAsync(sleepTimeoutInMilliseconds!);
      // checks if waiting shall be cancelled...
      shallCancel = await this.executeWaitCancellationCallbackAsync(callback);
    }
  }
}
