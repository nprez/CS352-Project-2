import bwapi.*;
import bwta.BWTA;
import bwta.BaseLocation;

public class EconomyManager extends DefaultBWListener{

    Player self;
    Game game;
    Mirror mirror;

    public EconomyManager(Player player, Game g, Mirror m){
        self = player;
        game = g;
        mirror = m;
    }

    @Override
    public void onFrame() {
        StringBuilder units = new StringBuilder("My units:\n");
        //iterate through my units
        for (Unit myUnit : self.getUnits()) {
            units.append(myUnit.getType()).append(" ").append(myUnit.getTilePosition()).append("\n");

            buildWorkers(myUnit);
            sendToMine(myUnit);
        }
    }

    public void sendToMine(Unit myUnit){
        //if it's a worker and it's idle, send it to the closest mineral patch
        if (myUnit.getType().isWorker() && myUnit.isIdle()) {
            Unit closestMineral = null;

            //find the closest mineral
            for (Unit neutralUnit : game.neutral().getUnits()) {
                if (neutralUnit.getType().isMineralField()) {
                    if (closestMineral == null || myUnit.getDistance(neutralUnit) < myUnit.getDistance(closestMineral)) {
                        closestMineral = neutralUnit;
                    }
                }
            }

            //if a mineral patch was found, send the worker to gather it
            if (closestMineral != null) {
                myUnit.gather(closestMineral, false);
            }
        }
    }

    public void buildWorkers(Unit myUnit){
        //if there's enough minerals, train a probe
        if (myUnit.getType() == UnitType.Protoss_Nexus && self.minerals() >= 50 && !myUnit.isTraining()) {
            myUnit.train(UnitType.Protoss_Probe);
        }
    }
}
