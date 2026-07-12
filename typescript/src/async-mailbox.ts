// AsyncMailbox adapts an event-driven producer (e.g. a Node stream emitting
// 'data'/'error'/'end') into a Promise-based `recv()` a consumer can `await`
// in a loop, mirroring the blocking `Recv() (T, error)` shape the Go client
// depends on for both AcquireRestartLock and WatchServiceBundle. Values are
// buffered if they arrive before anyone calls next(); a terminal state
// (error or done) is latched permanently once reached, so every subsequent
// next() call after the stream ends resolves to that same terminal item
// instead of hanging forever.

export type MailboxItem<T> = { kind: "value"; value: T } | { kind: "error"; error: Error } | { kind: "done" };

export class AsyncMailbox<T> {
  private readonly buffered: T[] = [];
  private readonly waiters: Array<(item: MailboxItem<T>) => void> = [];
  private terminal: MailboxItem<T> | undefined;

  pushValue(value: T): void {
    if (this.terminal) return;
    const waiter = this.waiters.shift();
    if (waiter) {
      waiter({ kind: "value", value });
    } else {
      this.buffered.push(value);
    }
  }

  pushTerminal(item: MailboxItem<T>): void {
    if (this.terminal) return;
    this.terminal = item;
    while (this.waiters.length > 0) {
      this.waiters.shift()!(item);
    }
  }

  next(): Promise<MailboxItem<T>> {
    if (this.buffered.length > 0) {
      return Promise.resolve({ kind: "value", value: this.buffered.shift()! });
    }
    if (this.terminal) {
      return Promise.resolve(this.terminal);
    }
    return new Promise((resolve) => this.waiters.push(resolve));
  }
}
