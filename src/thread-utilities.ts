const WAITING_THREAD_SLEEP_TIMEOUT_IN_MILLISECONDS = 1 * 1000;

type WaitCancellationCallback = () => boolean | Promise<boolean>;

export class ThreadUtilities {

  /**
   * Suspends the current thread for the specified number of milliseconds.
   * @param timeoutInMilliseconds The number of milliseconds for which the thread is suspended.
   * @returns A promise that resolves to void.
   */
  public static async sleepAsync(timeoutInMilliseconds: number): Promise<void> {
    return new Promise<void>(resolve => {
      if (timeoutInMilliseconds < 1) {
        timeoutInMilliseconds = 10;
      }

      const timeout = setTimeout(() => {
        // clears the timeout object...
        clearTimeout(timeout);
        // resolves the promise...
        resolve();
      }, timeoutInMilliseconds);
    });
  }

  public static async waitAsync(callback?: WaitCancellationCallback): Promise<void> {
    let shallCancel = typeof callback === "function" ? await callback() : false;

    while (!shallCancel) {
      // suspends the waiting thread for a certain time...
      await this.sleepAsync(WAITING_THREAD_SLEEP_TIMEOUT_IN_MILLISECONDS);
      // checks if waiting shall be cancelled...
      shallCancel = typeof callback === "function" ? await callback() : false;
    }
  }
}
