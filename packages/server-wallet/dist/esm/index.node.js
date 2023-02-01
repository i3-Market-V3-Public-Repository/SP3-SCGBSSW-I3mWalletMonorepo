import { NullDialog, FileStore, ConsoleToast } from '@i3m/base-wallet';
import { homedir } from 'os';
import { join } from 'path';
import walletBuilder from '@i3m/bok-wallet';
import { mkdirSync, rmSync } from 'fs';

async function serverWalletBuilder(options) {
    let filepath;
    if (options?.filepath === undefined) {
        const filedir = join(homedir(), '.server-wallet');
        try {
            mkdirSync(filedir);
        }
        catch (error) { }
        filepath = join(filedir, 'store');
    }
    else {
        filepath = options.filepath;
    }
    if (options?.reset === true) {
        try {
            rmSync(filepath);
        }
        catch (error) { }
    }
    const dialog = new NullDialog();
    const store = new FileStore(filepath, options?.password);
    const toast = new ConsoleToast();
    return await walletBuilder({
        dialog,
        store,
        toast,
        provider: options?.provider,
        providersData: options?.providerData
    });
}

export { serverWalletBuilder };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL2luZGV4LnRzIl0sInNvdXJjZXNDb250ZW50IjpudWxsLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7QUFxQk8sZUFBZSxtQkFBbUIsQ0FBRSxPQUE2QixFQUFBO0FBQ3RFLElBQUEsSUFBSSxRQUFnQixDQUFBO0FBQ3BCLElBQUEsSUFBSSxPQUFPLEVBQUUsUUFBUSxLQUFLLFNBQVMsRUFBRTtRQUNuQyxNQUFNLE9BQU8sR0FBRyxJQUFJLENBQUMsT0FBTyxFQUFFLEVBQUUsZ0JBQWdCLENBQUMsQ0FBQTtRQUNqRCxJQUFJO1lBQ0YsU0FBUyxDQUFDLE9BQU8sQ0FBQyxDQUFBO0FBQ25CLFNBQUE7UUFBQyxPQUFPLEtBQUssRUFBRSxHQUFHO0FBQ25CLFFBQUEsUUFBUSxHQUFHLElBQUksQ0FBQyxPQUFPLEVBQUUsT0FBTyxDQUFDLENBQUE7QUFDbEMsS0FBQTtBQUFNLFNBQUE7QUFDTCxRQUFBLFFBQVEsR0FBRyxPQUFPLENBQUMsUUFBUSxDQUFBO0FBQzVCLEtBQUE7QUFDRCxJQUFBLElBQUksT0FBTyxFQUFFLEtBQUssS0FBSyxJQUFJLEVBQUU7UUFDM0IsSUFBSTtZQUNGLE1BQU0sQ0FBQyxRQUFRLENBQUMsQ0FBQTtBQUNqQixTQUFBO1FBQUMsT0FBTyxLQUFLLEVBQUUsR0FBRztBQUNwQixLQUFBO0FBQ0QsSUFBQSxNQUFNLE1BQU0sR0FBRyxJQUFJLFVBQVUsRUFBRSxDQUFBO0lBQy9CLE1BQU0sS0FBSyxHQUFHLElBQUksU0FBUyxDQUFpQixRQUFRLEVBQUUsT0FBTyxFQUFFLFFBQVEsQ0FBQyxDQUFBO0FBQ3hFLElBQUEsTUFBTSxLQUFLLEdBQUcsSUFBSSxZQUFZLEVBQUUsQ0FBQTtJQUNoQyxPQUFPLE1BQU8sYUFBYSxDQUFDO1FBQzFCLE1BQU07UUFDTixLQUFLO1FBQ0wsS0FBSztRQUNMLFFBQVEsRUFBRSxPQUFPLEVBQUUsUUFBUTtRQUMzQixhQUFhLEVBQUUsT0FBTyxFQUFFLFlBQVk7QUFDckMsS0FBQSxDQUEyQixDQUFBO0FBQzlCOzs7OyJ9
