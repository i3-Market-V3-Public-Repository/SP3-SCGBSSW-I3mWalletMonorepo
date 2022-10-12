import { NullDialog, FileStore, ConsoleToast } from '@i3m/base-wallet';
import { homedir } from 'os';
import { join } from 'path';
import walletBuilder from '@i3m/bok-wallet';
import { mkdirSync } from 'fs';

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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL2luZGV4LnRzIl0sInNvdXJjZXNDb250ZW50IjpudWxsLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7QUFvQk8sZUFBZSxtQkFBbUIsQ0FBRSxPQUE2QixFQUFBO0FBQ3RFLElBQUEsSUFBSSxRQUFnQixDQUFBO0FBQ3BCLElBQUEsSUFBSSxPQUFPLEVBQUUsUUFBUSxLQUFLLFNBQVMsRUFBRTtRQUNuQyxNQUFNLE9BQU8sR0FBRyxJQUFJLENBQUMsT0FBTyxFQUFFLEVBQUUsZ0JBQWdCLENBQUMsQ0FBQTtRQUNqRCxJQUFJO1lBQ0YsU0FBUyxDQUFDLE9BQU8sQ0FBQyxDQUFBO0FBQ25CLFNBQUE7UUFBQyxPQUFPLEtBQUssRUFBRSxHQUFHO0FBQ25CLFFBQUEsUUFBUSxHQUFHLElBQUksQ0FBQyxPQUFPLEVBQUUsT0FBTyxDQUFDLENBQUE7QUFDbEMsS0FBQTtBQUFNLFNBQUE7QUFDTCxRQUFBLFFBQVEsR0FBRyxPQUFPLENBQUMsUUFBUSxDQUFBO0FBQzVCLEtBQUE7QUFDRCxJQUFBLE1BQU0sTUFBTSxHQUFHLElBQUksVUFBVSxFQUFFLENBQUE7SUFDL0IsTUFBTSxLQUFLLEdBQUcsSUFBSSxTQUFTLENBQUMsUUFBUSxFQUFFLE9BQU8sRUFBRSxRQUFRLENBQUMsQ0FBQTtBQUN4RCxJQUFBLE1BQU0sS0FBSyxHQUFHLElBQUksWUFBWSxFQUFFLENBQUE7SUFDaEMsT0FBTyxNQUFPLGFBQWEsQ0FBQztRQUMxQixNQUFNO1FBQ04sS0FBSztRQUNMLEtBQUs7UUFDTCxRQUFRLEVBQUUsT0FBTyxFQUFFLFFBQVE7UUFDM0IsYUFBYSxFQUFFLE9BQU8sRUFBRSxZQUFZO0FBQ3JDLEtBQUEsQ0FBMkIsQ0FBQTtBQUM5Qjs7OzsifQ==
