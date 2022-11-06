"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildMenuBar = void 0;
const lib_1 = require("@wallet/lib");
const electron_1 = require("electron");
const buildMenuBar = (locals) => {
    const template = [
        {
            label: 'File',
            submenu: [
                {
                    label: 'Reset',
                    click: async () => await locals.actionReducer.reduce(lib_1.resetAction.create())
                },
                {
                    type: 'separator'
                },
                {
                    label: 'Close',
                    accelerator: 'CommandOrControl+W',
                    role: 'close'
                }
            ]
        },
        {
            label: 'Edit',
            submenu: [
                {
                    label: 'Undo',
                    accelerator: 'CommandOrControl+Z',
                    role: 'undo'
                },
                {
                    label: 'Redo',
                    accelerator: 'Shift+CommandOrControl+Z',
                    role: 'redo'
                },
                { type: 'separator' },
                {
                    label: 'Cut',
                    accelerator: 'CommandOrControl+X',
                    role: 'cut'
                },
                {
                    label: 'Copy',
                    accelerator: 'CommandOrControl+C',
                    role: 'copy'
                },
                {
                    label: 'Paste',
                    accelerator: 'CommandOrControl+V',
                    role: 'paste'
                },
                {
                    label: 'Select All',
                    accelerator: 'CommandOrControl+A',
                    role: 'selectAll'
                }
            ]
        },
        {
            label: 'Window',
            submenu: [
                {
                    label: 'Minimize',
                    accelerator: 'CommandOrControl+M',
                    role: 'minimize'
                }
            ]
        }
    ];
    if (process.platform === 'darwin') {
        const name = electron_1.app.getName();
        template.unshift({ label: name });
    }
    return electron_1.Menu.buildFromTemplate(template);
};
exports.buildMenuBar = buildMenuBar;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibWVudS1iYXIuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi8uLi9zcmMvbWFpbi91aS93aW5kb3ctbWFuYWdlci9tZW51LWJhci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFBQSxxQ0FBeUM7QUFFekMsdUNBQW9DO0FBSTdCLE1BQU0sWUFBWSxHQUFHLENBQUMsTUFBYyxFQUFRLEVBQUU7SUFDbkQsTUFBTSxRQUFRLEdBQWE7UUFDekI7WUFDRSxLQUFLLEVBQUUsTUFBTTtZQUNiLE9BQU8sRUFBRTtnQkFDUDtvQkFDRSxLQUFLLEVBQUUsT0FBTztvQkFDZCxLQUFLLEVBQUUsS0FBSyxJQUFJLEVBQUUsQ0FBQyxNQUFNLE1BQU0sQ0FBQyxhQUFhLENBQUMsTUFBTSxDQUFDLGlCQUFXLENBQUMsTUFBTSxFQUFFLENBQUM7aUJBQzNFO2dCQUNEO29CQUNFLElBQUksRUFBRSxXQUFXO2lCQUNsQjtnQkFDRDtvQkFDRSxLQUFLLEVBQUUsT0FBTztvQkFDZCxXQUFXLEVBQUUsb0JBQW9CO29CQUNqQyxJQUFJLEVBQUUsT0FBTztpQkFDZDthQUNGO1NBQ0Y7UUFDRDtZQUNFLEtBQUssRUFBRSxNQUFNO1lBQ2IsT0FBTyxFQUFFO2dCQUNQO29CQUNFLEtBQUssRUFBRSxNQUFNO29CQUNiLFdBQVcsRUFBRSxvQkFBb0I7b0JBQ2pDLElBQUksRUFBRSxNQUFNO2lCQUNiO2dCQUNEO29CQUNFLEtBQUssRUFBRSxNQUFNO29CQUNiLFdBQVcsRUFBRSwwQkFBMEI7b0JBQ3ZDLElBQUksRUFBRSxNQUFNO2lCQUNiO2dCQUNELEVBQUUsSUFBSSxFQUFFLFdBQVcsRUFBRTtnQkFDckI7b0JBQ0UsS0FBSyxFQUFFLEtBQUs7b0JBQ1osV0FBVyxFQUFFLG9CQUFvQjtvQkFDakMsSUFBSSxFQUFFLEtBQUs7aUJBQ1o7Z0JBQ0Q7b0JBQ0UsS0FBSyxFQUFFLE1BQU07b0JBQ2IsV0FBVyxFQUFFLG9CQUFvQjtvQkFDakMsSUFBSSxFQUFFLE1BQU07aUJBQ2I7Z0JBQ0Q7b0JBQ0UsS0FBSyxFQUFFLE9BQU87b0JBQ2QsV0FBVyxFQUFFLG9CQUFvQjtvQkFDakMsSUFBSSxFQUFFLE9BQU87aUJBQ2Q7Z0JBQ0Q7b0JBQ0UsS0FBSyxFQUFFLFlBQVk7b0JBQ25CLFdBQVcsRUFBRSxvQkFBb0I7b0JBQ2pDLElBQUksRUFBRSxXQUFXO2lCQUNsQjthQUNGO1NBQ0Y7UUFDRDtZQUNFLEtBQUssRUFBRSxRQUFRO1lBQ2YsT0FBTyxFQUFFO2dCQUNQO29CQUNFLEtBQUssRUFBRSxVQUFVO29CQUNqQixXQUFXLEVBQUUsb0JBQW9CO29CQUNqQyxJQUFJLEVBQUUsVUFBVTtpQkFDakI7YUFDRjtTQUNGO0tBQ0YsQ0FBQTtJQUVELElBQUksT0FBTyxDQUFDLFFBQVEsS0FBSyxRQUFRLEVBQUU7UUFDakMsTUFBTSxJQUFJLEdBQUcsY0FBRyxDQUFDLE9BQU8sRUFBRSxDQUFBO1FBQzFCLFFBQVEsQ0FBQyxPQUFPLENBQUMsRUFBRSxLQUFLLEVBQUUsSUFBSSxFQUFFLENBQUMsQ0FBQTtLQUNsQztJQUVELE9BQU8sZUFBSSxDQUFDLGlCQUFpQixDQUFDLFFBQVEsQ0FBQyxDQUFBO0FBQ3pDLENBQUMsQ0FBQTtBQXpFWSxRQUFBLFlBQVksZ0JBeUV4QiJ9